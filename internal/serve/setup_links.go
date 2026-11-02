package serve

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"github.com/picatz/doh/internal/httpsec"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
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
	httpsec.Page(h, r, setupCSP)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex")

	link, ok := s.setupLinks.lookup(r.PathValue("code"))
	pr := s.engine.Load().Policy().Profile(link.profile)
	if !ok || pr == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = setupTemplate.ExecuteTemplate(w, "expired", nil)
		return
	}

	// The link fixes the device: files are made for it, whatever the
	// request's query says.
	switch file := r.PathValue("file"); {
	case file == mobileConfigFile:
		s.serveMobileConfig(w, r, pr, link.device)
		return
	case slices.Contains(setupFiles, file):
		s.serveSetupFile(w, r, pr, link.device, file)
		return
	case file != "":
		http.NotFound(w, r)
		return
	}

	setup := s.setupFor(r.Context(), pr, link.device)
	base := setupPath + r.PathValue("code") + "/"
	page := setupPageData{
		Profile: cmp.Or(pr.Name, pr.ID),
		Device:  link.device,
		Minutes: strconv.Itoa(max(1, int(time.Until(link.expires).Round(time.Minute)/time.Minute))),
		DoHURL:  setup.DoHURL,
		DoTHost: setup.DoTHost,
	}
	for _, p := range setup.Platforms {
		if p.ID == "apple" && p.Signing != nil {
			page.SigningNote = p.Signing.Note
		}
	}
	if setup.DoHURL != "" || setup.DoTHost != "" {
		page.Download = base + mobileConfigFile
	}
	for _, g := range setup.Groups {
		group := setupPageGroup{Name: g.Name}
		for _, p := range setup.Platforms {
			if p.Group == g.ID {
				group.Platforms = append(group.Platforms, newSetupPagePlatform(p, base))
			}
		}
		page.Groups = append(page.Groups, group)
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	_ = setupTemplate.ExecuteTemplate(w, "setup", page)
}

// setupPageData is what a setup link's page shows.
type setupPageData struct {
	Profile, Device, Minutes string
	DoHURL, DoTHost          string

	// Download is the Apple configuration profile, for one-tap install.
	Download string

	// SigningNote says why the profile shows as unverified, if it will.
	SigningNote string

	Groups []setupPageGroup
}

// setupPageGroup is a group of platforms on a setup page.
type setupPageGroup struct {
	Name      string
	Platforms []setupPagePlatform
}

// setupPagePlatform is a platform on a setup page, with its downloads
// served under the link.
type setupPagePlatform struct {
	api.Platform
	Level, Badge string
	Files        []setupPageFile
}

// setupPageFile is a download on a setup page.
type setupPageFile struct {
	Name, Href string
}

// newSetupPagePlatform returns p for a setup page whose files are under
// base, as setupPath + code + "/".
func newSetupPagePlatform(p api.Platform, base string) setupPagePlatform {
	out := setupPagePlatform{Platform: p}
	if p.Protection != nil {
		out.Level = p.Protection.Level
		out.Badge = map[string]string{
			api.ProtectionEncrypted:   "Encrypted",
			api.ProtectionPlain:       "Plain DNS",
			api.ProtectionUnavailable: "Not available here",
		}[p.Protection.Level]
	}
	for _, d := range p.Downloads {
		u, err := url.Parse(d.Path)
		if err != nil {
			continue
		}
		// The link names the device; only the variant (protocol, lock)
		// comes from the query.
		q := u.Query()
		q.Del("device")
		href := base + path.Base(u.Path)
		if len(q) > 0 {
			href += "?" + q.Encode()
		}
		out.Files = append(out.Files, setupPageFile{Name: d.Name, Href: href})
	}
	return out
}

//go:embed setup_page.html
var setupFS embed.FS

var setupTemplate = template.Must(template.ParseFS(setupFS, "setup_page.html"))

// setupCSP is the setup page's content security policy: no scripts at
// all, and only its own stylesheet, allowed by its hash rather than any
// inline style.
var setupCSP = func() string {
	page, err := setupFS.ReadFile("setup_page.html")
	if err != nil {
		panic(err)
	}
	css, ok := httpsec.InlineStyle(string(page))
	if !ok {
		panic("setup_page.html has no <style>")
	}
	return "default-src 'none'; style-src " + httpsec.StyleHash(css) + "; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; " + httpsec.TrustedTypes
}()
