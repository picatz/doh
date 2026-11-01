package serve

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/plist"
	"github.com/picatz/doh/internal/policy"
)

// setupFor describes how to point a device at a profile.
func (s *Server) setupFor(pr *policy.Profile, device string) api.Setup {
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

	if dnsAddr := s.listenerAddr("dns"); dnsAddr != "" {
		if addr, err := net.ResolveUDPAddr("udp", dnsAddr); err == nil {
			for _, a := range lanAddrs(addr) {
				setup.DNSAddrs = append(setup.DNSAddrs, a.String())
			}
		}
	}

	setup.Platforms = s.platforms(setup, pr, dotPort)
	return setup
}

// platforms returns step-by-step instructions for each platform.
func (s *Server) platforms(setup api.Setup, pr *policy.Profile, dotPort string) []api.Platform {
	var platforms []api.Platform
	add := func(id, name string, steps ...string) *api.Platform {
		platforms = append(platforms, api.Platform{ID: id, Name: name, Steps: steps})
		return &platforms[len(platforms)-1]
	}

	serverIP := "<this server's IP address>"
	if len(setup.DNSAddrs) > 0 {
		serverIP = setup.DNSAddrs[0]
	}

	if setup.DoHURL != "" || setup.DoTHost != "" {
		p := add("apple", "iPhone, iPad, and Mac",
			"Download the configuration profile below on the device, or AirDrop it there.",
			"iPhone and iPad: open Settings, tap Profile Downloaded, then Install. Mac: open System Settings, then Privacy & Security, then Profiles, and install it.",
			"The profile applies on every network. Remove it from the same place to stop.",
		)
		p.Download = fmt.Sprintf("%s/profiles/%s/apple.mobileconfig", api.Prefix, url.PathEscape(pr.ID))
		if setup.Device != "" {
			p.Download += "?device=" + url.QueryEscape(setup.Device)
		}
	}

	if setup.DoTHost != "" {
		p := add("android", "Android",
			"Open Settings, then Network & internet (or Connections), then Private DNS.",
			"Choose Private DNS provider hostname, enter "+setup.DoTHost+", and save.",
		)
		if dotPort != "853" {
			p.Steps = append(p.Steps, "Android only connects on port 853, so make sure this server's DoT listener is reachable there.")
		}
	}

	if setup.DoHURL != "" {
		add("browser", "Chrome, Edge, Firefox, and Brave",
			"Chrome, Edge, and Brave: Settings, then Privacy and security, then Security, then Use secure DNS: choose Custom and enter "+setup.DoHURL+".",
			"Firefox: Settings, then Privacy & Security, then DNS over HTTPS: choose Max Protection, then Custom, and enter "+setup.DoHURL+".",
		)
		add("windows", "Windows 11",
			"Open Settings, then Network & internet, then your connection, then DNS server assignment: Edit.",
			"Choose Manual, turn on IPv4, enter "+serverIP+" as the preferred DNS, and set DNS over HTTPS to On (manual template) with "+setup.DoHURL+".",
		)
	}

	if setup.DoTHost != "" {
		add("linux", "Linux (systemd-resolved)",
			"In /etc/systemd/resolved.conf, under [Resolve], set DNS="+serverIP+"#"+setup.DoTHost+" and DNSOverTLS=yes.",
			"Run sudo systemctl restart systemd-resolved, then resolvectl status to check.",
		)
	}

	if len(setup.DNSAddrs) > 0 {
		steps := []string{"Set your router's DHCP DNS server to " + strings.Join(setup.DNSAddrs, " or ") + ", so every device on the network uses this server."}
		if len(pr.Clients) == 0 && len(pr.Devices) == 0 && pr.ID != policy.DefaultProfile {
			steps = append(steps, "Over plain DNS, devices are matched to profiles by address: add the device's address to this profile's devices or clients.")
		}
		add("router", "Your whole network", steps...)
	}

	if len(platforms) == 0 {
		step := "Set --hostname to this server's public name and serve DoH or DoT (--dot-listen :853) with a certificate to connect devices from anywhere, or --dns-listen :53 for devices on this network."
		if pr.Tenant != "" {
			// Tenants can't change how the server runs; their operator can.
			step = "This server isn't reachable by name yet. Ask its operator to give it a public host name and serve encrypted DNS, so devices can connect from anywhere."
		}
		add("none", "Nothing to set up yet", step)
	}
	return platforms
}

func (s *Server) apiSetup(w http.ResponseWriter, r *http.Request) {
	pr, device, ok := s.setupRequest(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.setupFor(pr, device))
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
	setup := s.setupFor(pr, device)

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
	_ = plist.Encode(w, mobileConfig(name, id, dns))
}

// mobileConfig returns a configuration profile with one encrypted DNS
// settings payload.
func mobileConfig(name, id string, dns plist.Dict) plist.Dict {
	return plist.Dict{
		{Key: "PayloadContent", Value: plist.Array{plist.Dict{
			{Key: "DNSSettings", Value: dns},
			{Key: "PayloadDisplayName", Value: plist.String("Encrypted DNS: " + name)},
			{Key: "PayloadIdentifier", Value: plist.String(id + ".dns")},
			{Key: "PayloadType", Value: plist.String("com.apple.dnsSettings.managed")},
			{Key: "PayloadUUID", Value: plist.String(uuidFor(id + ".dns"))},
			{Key: "PayloadVersion", Value: plist.Integer(1)},
		}}},
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
