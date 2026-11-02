package serve

import (
	"cmp"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/devicesetup"
	"github.com/picatz/doh/internal/plist"
	"github.com/picatz/doh/internal/policy"
)

// setupFor describes how to point a device at a profile.
func (s *Server) setupFor(ctx context.Context, pr *policy.Profile, device string) api.Setup {
	setup := api.Setup{Profile: pr.ID, Device: device, Hostname: s.config.Hostname}

	if s.config.Hostname != "" && s.config.servesDoH() {
		u := url.URL{Scheme: "https", Host: s.config.Hostname, Path: strings.TrimSuffix(s.config.Path, "/") + "/" + pr.ID}
		if device != "" {
			u.Path += "/" + device
		}
		setup.DoHURL = u.String()
	}

	dotPort := ""
	if s.config.DoTListen != "" {
		setup.DoTHost = s.profileHost(pr.ID, device)
		_, dotPort, _ = net.SplitHostPort(s.config.DoTListen)
	}

	var lan []netip.Addr
	if dnsAddr := s.listenerAddr("dns"); dnsAddr != "" {
		if addr, err := net.ResolveUDPAddr("udp", dnsAddr); err == nil {
			lan = lanAddrs(addr)
			for _, a := range lan {
				setup.DNSAddrs = append(setup.DNSAddrs, a.String())
			}
		}
	}

	if setup.DoHURL != "" || setup.DoTHost != "" {
		addrs := s.selfAddrs.get(ctx, s.config.Hostname)
		if len(addrs) == 0 {
			// The encrypted listeners are on this machine too, and listen
			// on every address unless told otherwise.
			addrs = lan
		}
		for _, a := range addrs {
			setup.ServerAddrs = append(setup.ServerAddrs, a.String())
		}
	}

	setup.Platforms, setup.Groups = platformsFor(setupInputs{
		setup:     setup,
		tenant:    pr.Tenant != "",
		isDefault: pr.ID == policy.DefaultProfile,
		listed:    len(pr.Clients) > 0 || len(pr.Devices) > 0,
		dotPort:   dotPort,
	})
	return setup
}

// selfAddrs looks up the server's own host name, for settings that pair
// an address with it, remembering the answer for a while. The zero value
// is ready to use; it's safe for concurrent use.
type selfAddrs struct {
	// lookup looks host up; nil means net.DefaultResolver.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)

	mu      sync.Mutex
	host    string
	addrs   []netip.Addr
	expires time.Time
}

const (
	// selfAddrsTTL is how long a lookup of the server's name is kept,
	// and selfAddrsRetry how long a failed one is.
	selfAddrsTTL   = 10 * time.Minute
	selfAddrsRetry = time.Minute

	// selfAddrsTimeout bounds each lookup.
	selfAddrsTimeout = 2 * time.Second
)

// get returns the addresses host resolves to that devices could connect
// to: not loopback, link-local, or unspecified, and at most
// devicesetup.MaxAddrs of them.
func (c *selfAddrs) get(ctx context.Context, host string) []netip.Addr {
	if host == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.host == host && time.Now().Before(c.expires) {
		return c.addrs
	}

	lookup := c.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), selfAddrsTimeout)
	defer cancel()
	found, err := lookup(ctx, host)

	var addrs []netip.Addr
	for _, a := range found {
		a = a.Unmap().WithZone("")
		if a.IsValid() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsUnspecified() && !a.IsMulticast() && !slices.Contains(addrs, a) && len(addrs) < devicesetup.MaxAddrs {
			addrs = append(addrs, a)
		}
	}
	c.host, c.addrs, c.expires = host, addrs, time.Now().Add(selfAddrsTTL)
	if err != nil || len(addrs) == 0 {
		c.expires = time.Now().Add(selfAddrsRetry)
	}
	return addrs
}

func (s *Server) apiSetup(w http.ResponseWriter, r *http.Request) {
	pr, device, ok := s.setupRequest(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.setupFor(r.Context(), pr, device))
}

// setupRequest reads the profile and device a setup request is for,
// writing any error.
func (s *Server) setupRequest(w http.ResponseWriter, r *http.Request) (*policy.Profile, string, bool) {
	pr := s.engine.Load().Policy().Profile(r.PathValue("id"))
	if !principalOf(r).sees(pr) {
		writeError(w, http.StatusNotFound, "no profile "+strconv.Quote(r.PathValue("id")))
		return nil, "", false
	}
	device := r.URL.Query().Get("device")
	if device != "" && !policy.ValidID(device) {
		writeError(w, http.StatusBadRequest, "device names are 1 to 63 lower-case letters, digits, and single hyphens")
		return nil, "", false
	}
	return pr, device, true
}

// apiMobileConfig serves an Apple configuration profile that points the
// device's DNS at the profile over DoH, or with protocol=tls, DoT, using
// the encrypted DNS settings payload Apple documents for iOS 14, macOS 11,
// and later.
//
// The configuration profile isn't signed, so devices show it as
// unverified. Its identifiers are derived from the server, profile, and
// device, so downloading it again replaces the installed copy rather than
// adding another.
func (s *Server) apiMobileConfig(w http.ResponseWriter, r *http.Request) {
	pr, device, ok := s.setupRequest(w, r)
	if !ok {
		return
	}
	s.serveMobileConfig(w, r, pr, device)
}

// apiSetupFile serves one of setupFiles for a profile, and a device if
// named.
func (s *Server) apiSetupFile(file string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pr, device, ok := s.setupRequest(w, r)
		if !ok {
			return
		}
		s.serveSetupFile(w, r, pr, device, file)
	}
}

// serveMobileConfig writes the Apple configuration profile for pr and
// device, over DoH or, with protocol=tls, DoT. With lock=true, the DNS
// settings can't be turned off on supervised devices.
func (s *Server) serveMobileConfig(w http.ResponseWriter, r *http.Request, pr *policy.Profile, device string) {
	setup := s.setupFor(r.Context(), pr, device)

	var extra []plist.Entry
	if v := r.URL.Query().Get("lock"); v != "" {
		lock, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "lock must be true or false")
			return
		}
		if lock {
			// Apple honors ProhibitDisablement on supervised devices only.
			extra = append(extra, plist.Entry{Key: "ProhibitDisablement", Value: plist.Bool(true)})
		}
	}

	dns := plist.Dict{{Key: "DNSProtocol", Value: plist.String("HTTPS")}, {Key: "ServerURL", Value: plist.String(setup.DoHURL)}}
	switch protocol := r.URL.Query().Get("protocol"); {
	case protocol == "tls" || (protocol == "" && setup.DoHURL == ""):
		if setup.DoTHost == "" {
			writeError(w, http.StatusConflict, "this server doesn't serve DoT under a hostname; set --hostname and --dot-listen")
			return
		}
		dns = plist.Dict{{Key: "DNSProtocol", Value: plist.String("TLS")}, {Key: "ServerName", Value: plist.String(setup.DoTHost)}}
	case protocol != "" && protocol != "https":
		writeError(w, http.StatusBadRequest, "protocol must be https or tls")
		return
	case setup.DoHURL == "":
		writeError(w, http.StatusConflict, "this server doesn't serve DoH under a hostname; set --hostname and serve DoH with a certificate")
		return
	}

	name, id, filename := cmp.Or(pr.Name, pr.ID), "doh."+s.config.Hostname+"."+pr.ID, pr.ID
	if device != "" {
		name, id, filename = name+" ("+device+")", id+"."+device, filename+"-"+device
	}

	w.Header().Set("Content-Type", api.MobileConfigType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`.mobileconfig"`)
	_ = plist.Encode(w, mobileConfig(name, id, dns, extra...))
}

// serveSetupFile writes one of setupFiles for pr and device, made from the
// profile's setup.
func (s *Server) serveSetupFile(w http.ResponseWriter, r *http.Request, pr *policy.Profile, device, file string) {
	setup := s.setupFor(r.Context(), pr, device)
	serverAddrs, dnsAddrs := parseAddrs(setup.ServerAddrs), parseAddrs(setup.DNSAddrs)

	var b []byte
	var err error
	switch file {
	case devicesetup.WindowsFile:
		if setup.DoHURL == "" {
			writeError(w, http.StatusConflict, "Windows' encrypted DNS needs this server's DoH under a host name, which it doesn't serve")
			return
		}
		b, err = devicesetup.WindowsScript(devicesetup.Windows{Template: setup.DoHURL, Addrs: serverAddrs, Profile: pr.ID, Device: device})
	case devicesetup.ResolvedFile:
		switch {
		case setup.DoTHost == "":
			writeError(w, http.StatusConflict, "systemd-resolved's encrypted DNS needs this server's DoT under a host name, which it doesn't serve")
			return
		case len(serverAddrs) == 0:
			writeError(w, http.StatusConflict, "doh couldn't find this server's address, which systemd-resolved needs: write DNS="+"<address>#"+setup.DoTHost+" yourself")
			return
		}
		b, err = devicesetup.ResolvedDropIn(devicesetup.Resolved{ServerName: setup.DoTHost, Addrs: serverAddrs, Profile: pr.ID, Device: device})
	case devicesetup.OpenWrtFile:
		if len(dnsAddrs) == 0 {
			writeError(w, http.StatusConflict, "OpenWrt hands out this server's plain DNS address, which it doesn't serve on a local network")
			return
		}
		b, err = devicesetup.OpenWrtScript(devicesetup.OpenWrt{Addrs: dnsAddrs, Profile: pr.ID})
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "making "+file+" failed")
		return
	}
	w.Header().Set("Content-Type", api.TextFileType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	_, _ = w.Write(b)
}

// parseAddrs parses addresses, skipping any that don't parse.
func parseAddrs(addrs []string) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil {
			out = append(out, ip)
		}
	}
	return out
}

// mobileConfig returns a configuration profile with one encrypted DNS
// settings payload, with extra entries, such as ProhibitDisablement, in
// that payload.
func mobileConfig(name, id string, dns plist.Dict, extra ...plist.Entry) plist.Dict {
	payload := plist.Dict{
		{Key: "DNSSettings", Value: dns},
		{Key: "PayloadDisplayName", Value: plist.String("Encrypted DNS: " + name)},
		{Key: "PayloadIdentifier", Value: plist.String(id + ".dns")},
		{Key: "PayloadType", Value: plist.String("com.apple.dnsSettings.managed")},
		{Key: "PayloadUUID", Value: plist.String(uuidFor(id + ".dns"))},
		{Key: "PayloadVersion", Value: plist.Integer(1)},
	}
	payload = append(payload, extra...)
	return plist.Dict{
		{Key: "PayloadContent", Value: plist.Array{payload}},
		{Key: "PayloadDescription", Value: plist.String("Sends this device's DNS queries to doh, encrypted, using profile " + name + ".")},
		{Key: "PayloadDisplayName", Value: plist.String("doh: " + name)},
		{Key: "PayloadIdentifier", Value: plist.String(id)},
		{Key: "PayloadRemovalDisallowed", Value: plist.Bool(false)},
		{Key: "PayloadType", Value: plist.String("Configuration")},
		{Key: "PayloadUUID", Value: plist.String(uuidFor(id))},
		{Key: "PayloadVersion", Value: plist.Integer(1)},
	}
}

// uuidFor derives a stable UUID from name, in the form of a version 8
// (custom) UUID ([RFC 9562, Section 5.8]), so the same profile always gets
// the same identifiers.
//
// [RFC 9562, Section 5.8]: https://www.rfc-editor.org/rfc/rfc9562.html#section-5.8
func uuidFor(name string) string {
	sum := sha256.Sum256([]byte("doh mobileconfig " + name))
	u := sum[:16]
	u[6] = u[6]&0x0f | 0x80 // version 8
	u[8] = u[8]&0x3f | 0x80 // RFC 9562 variant
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]))
}
