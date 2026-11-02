package serve

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/brand"
)

// Setup links let someone at the admin UI send a device what it needs to
// connect: a short-lived link to a page on the public listener, opened on
// the device itself, with one-tap install for Apple devices and plain
// steps for others.
//
// A link reveals only how to connect to one profile, which anyone who
// knows the profile's ID can already do; it expires so old links in chat
// histories go nowhere.
const (
	// SetupLinkTTL is how long a setup link works.
	SetupLinkTTL = 30 * time.Minute

	// maxSetupLinks bounds the links kept at once.
	maxSetupLinks = 1000

	// setupPath is where setup pages are served on the public listener.
	setupPath = "/setup/"
)

// setupLinks keeps setup links, by the SHA-256 of their codes. It's safe
// for concurrent use.
type setupLinks struct {
	mu    sync.Mutex
	links map[[sha256.Size]byte]setupLink
	now   func() time.Time
}

type setupLink struct {
	profile, device string
	expires         time.Time
}

func newSetupLinks() *setupLinks {
	return &setupLinks{links: make(map[[sha256.Size]byte]setupLink), now: time.Now}
}

// create makes a link for profile and device, returning its code.
func (l *setupLinks) create(profile, device string) (code string, expires time.Time, err error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", time.Time{}, err
	}
	code = base64.RawURLEncoding.EncodeToString(b[:])
	now := l.now()
	expires = now.Add(SetupLinkTTL)

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.links) >= maxSetupLinks {
		l.sweep(now)
	}
	if len(l.links) >= maxSetupLinks {
		// The oldest link expires soonest; it goes first.
		var oldest [sha256.Size]byte
		var when time.Time
		for k, v := range l.links {
			if when.IsZero() || v.expires.Before(when) {
				oldest, when = k, v.expires
			}
		}
		delete(l.links, oldest)
	}
	l.links[sha256.Sum256([]byte(code))] = setupLink{profile: profile, device: device, expires: expires}
	return code, expires, nil
}

// lookup returns the link with code, if it hasn't expired.
func (l *setupLinks) lookup(code string) (setupLink, bool) {
	if len(code) != 22 {
		return setupLink{}, false
	}
	key := sha256.Sum256([]byte(code))
	l.mu.Lock()
	defer l.mu.Unlock()
	link, ok := l.links[key]
	if !ok || !l.now().Before(link.expires) {
		delete(l.links, key)
		return setupLink{}, false
	}
	return link, true
}

// sweep drops expired links. l.mu must be held.
func (l *setupLinks) sweep(now time.Time) {
	for k, v := range l.links {
		if !now.Before(v.expires) {
			delete(l.links, k)
		}
	}
}

// apiSetupLink creates a setup link for a profile, and a device if named.
func (s *Server) apiSetupLink(w http.ResponseWriter, r *http.Request) {
	pr, device, ok := s.setupRequest(w, r)
	if !ok {
		return
	}
	base, ok := s.setupBase()
	if !ok {
		writeError(w, http.StatusConflict, "setup links need this server's public name and DoH: set --hostname and serve DoH with a certificate")
		return
	}
	code, expires, err := s.setupLinks.create(pr.ID, device)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "creating a setup link failed")
		return
	}
	s.audit(r, "setup link created", slog.String("profile", pr.ID), slog.String("device", device))
	link := api.SetupLink{URL: base + setupPath + code, Expires: expires}
	if d, err := brand.QR([]byte(link.URL)); err == nil {
		link.QR = &api.QRCode{SVG: d.SVG("QR code for the setup link")}
	}
	writeJSON(w, http.StatusCreated, link)
}

// setupBase returns the public listener's origin, if the server has one.
func (s *Server) setupBase() (string, bool) {
	if s.config.Hostname == "" || !s.config.servesDoH() {
		return "", false
	}
	return (&url.URL{Scheme: "https", Host: s.config.Hostname}).String(), true
}

// setupPage serves a setup link's page, or its Apple configuration
// profile, on the public listener.
func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

	link, ok := s.setupLinks.lookup(r.PathValue("code"))
	pr := s.engine.Load().Policy().Profile(link.profile)
	if !ok || pr == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = setupTemplate.ExecuteTemplate(w, "expired", nil)
		return
	}

	if r.PathValue("file") == "apple.mobileconfig" {
		s.serveMobileConfig(w, r, pr, link.device)
		return
	}
	if r.PathValue("file") != "" {
		http.NotFound(w, r)
		return
	}

	setup := s.setupFor(pr, link.device)
	page := setupPageData{
		Profile:  cmp.Or(pr.Name, pr.ID),
		Device:   link.device,
		Minutes:  strconv.Itoa(max(1, int(time.Until(link.expires).Round(time.Minute)/time.Minute))),
		DoHURL:   setup.DoHURL,
		DoTHost:  setup.DoTHost,
		Download: setupPath + r.PathValue("code") + "/apple.mobileconfig",
	}
	for _, p := range setup.Platforms {
		if p.ID != "apple" && p.ID != "router" && p.ID != "none" {
			page.Platforms = append(page.Platforms, p)
		}
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	_ = setupTemplate.ExecuteTemplate(w, "setup", page)
}

type setupPageData struct {
	Profile, Device, Minutes string
	DoHURL, DoTHost          string
	Download                 string
	Platforms                []api.Platform
}

//go:embed setup_page.html
var setupFS embed.FS

var setupTemplate = template.Must(template.ParseFS(setupFS, "setup_page.html"))
