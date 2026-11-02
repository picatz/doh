package serve

import (
	"cmp"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/devicesetup"
)

// setupInputs is what a profile's setup instructions depend on, so they
// can be worked out, and tested, as a pure function of it.
type setupInputs struct {
	// setup holds the profile, device, and how the server is reached.
	setup api.Setup

	// tenant is set when the profile belongs to a tenant, who can't change
	// how the server runs, so instructions never mention its flags.
	tenant bool

	// isDefault is set for the default profile, which clients no other
	// profile lists get.
	isDefault bool

	// listed is set when the profile lists clients or devices by address.
	listed bool

	// signing is whether, and how, configuration profiles are signed.
	signing *api.ProfileSigning

	// dotPort is the port the DoT listener is on, if it's on.
	dotPort string
}

// groupNames names the platform groups, in the order they're shown.
var groupNames = []api.PlatformGroup{
	{ID: api.GroupPhones, Name: "Phones & tablets"},
	{ID: api.GroupComputers, Name: "Computers"},
	{ID: api.GroupTV, Name: "TV & streaming"},
	{ID: api.GroupConsoles, Name: "Game consoles"},
	{ID: api.GroupSmartHome, Name: "Smart home"},
	{ID: api.GroupBrowsers, Name: "Browsers"},
	{ID: api.GroupNetwork, Name: "Whole network"},
}

// Setup files, by the name they're served under.
const mobileConfigFile = "apple.mobileconfig"

// setupFiles are the files setup can offer besides mobileConfigFile.
var setupFiles = []string{devicesetup.WindowsFile, devicesetup.ResolvedFile, devicesetup.OpenWrtFile}

// platformsFor returns the instructions for every platform, best
// protection first within each group, and the groups they're in.
func platformsFor(in setupInputs) ([]api.Platform, []api.PlatformGroup) {
	b := platformBuilder{setupInputs: in, Setup: in.setup}
	if b.DoHURL == "" && b.DoTHost == "" && len(b.DNSAddrs) == 0 {
		step := "Set --hostname to this server's public name and serve DoH or DoT (--dot-listen :853) with a certificate to connect devices from anywhere, or --dns-listen :53 for devices on this network."
		if in.tenant {
			// Tenants can't change how the server runs; their operator can.
			step = "This server isn't reachable by name yet. Ask its operator to give it a public host name and serve encrypted DNS, so devices can connect from anywhere."
		}
		return []api.Platform{{ID: "none", Name: "Nothing to set up yet", Steps: []string{step}}}, nil
	}

	b.apple()
	b.visionPro()
	b.android()
	b.mac()
	b.windows()
	b.linux()
	b.chromeOS()
	b.appleTV()
	b.androidTV()
	b.smartTV()
	b.consoles()
	b.smartHome()
	b.browsers()
	b.router()
	b.openWrt()
	b.pfSense()
	b.unifi()

	// Keep the order above within each group, and the groups' order.
	order := func(id string) int {
		return slices.IndexFunc(groupNames, func(g api.PlatformGroup) bool { return g.ID == id })
	}
	slices.SortStableFunc(b.platforms, func(x, y api.Platform) int { return order(x.Group) - order(y.Group) })

	var groups []api.PlatformGroup
	for _, g := range groupNames {
		if slices.ContainsFunc(b.platforms, func(p api.Platform) bool { return p.Group == g.ID }) {
			groups = append(groups, g)
		}
	}
	return b.platforms, groups
}

// platformBuilder collects platforms' instructions.
type platformBuilder struct {
	setupInputs
	api.Setup
	platforms []api.Platform
}

// add adds a platform, returning it to fill in.
func (b *platformBuilder) add(id, group, name string, protection api.Protection, steps ...string) *api.Platform {
	b.platforms = append(b.platforms, api.Platform{ID: id, Group: group, Name: name, Protection: &protection, Steps: steps})
	return &b.platforms[len(b.platforms)-1]
}

// download offers a file on p.
func (b *platformBuilder) download(p *api.Platform, name, file, filename, contentType string, q url.Values) {
	if q == nil {
		q = url.Values{}
	}
	if b.Device != "" && file != devicesetup.OpenWrtFile {
		q.Set("device", b.Device)
	}
	path := fmt.Sprintf("%s/profiles/%s/%s", api.Prefix, url.PathEscape(b.Profile), file)
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	p.Downloads = append(p.Downloads, api.Download{Name: name, File: filename, Path: path, ContentType: contentType})
	if p.Download == "" {
		p.Download = path
	}
}

// encrypted describes encrypted settings, preferring DoH.
func (b *platformBuilder) encrypted(onWhat string) api.Protection {
	if b.DoHURL != "" {
		return api.Protection{Level: api.ProtectionEncrypted, Protocol: "https", Summary: "Encrypted " + onWhat + ", with DNS-over-HTTPS."}
	}
	return api.Protection{Level: api.ProtectionEncrypted, Protocol: "tls", Summary: "Encrypted " + onWhat + ", with DNS-over-TLS."}
}

// plainDNS describes plain DNS settings.
func plainDNS(why string) api.Protection {
	return api.Protection{Level: api.ProtectionPlain, Protocol: "dns", Summary: why}
}

// unavailable describes a platform this server can't serve.
func unavailable(why string) api.Protection {
	return api.Protection{Level: api.ProtectionUnavailable, Summary: why}
}

// dnsAddr is the plain DNS address to give devices, as text.
func (b *platformBuilder) dnsAddr() string {
	if len(b.DNSAddrs) > 0 {
		return b.DNSAddrs[0]
	}
	return "this server's address"
}

// dnsAddrs is every plain DNS address, as text.
func (b *platformBuilder) dnsAddrs() string { return strings.Join(b.DNSAddrs, " or ") }

// serverAddr is an address the encrypted listeners are reached at,
// preferring IPv4, which every network has, or "" if none is known.
func (b *platformBuilder) serverAddr() string {
	for _, a := range b.ServerAddrs {
		if !strings.Contains(a, ":") {
			return a
		}
	}
	if len(b.ServerAddrs) > 0 {
		return b.ServerAddrs[0]
	}
	return ""
}

// serverAddrOr is serverAddr, or if none is known, the placeholder
// "<address>", with a step saying how to find it.
func (b *platformBuilder) serverAddrOr() (addr, find string) {
	if a := b.serverAddr(); a != "" {
		return a, ""
	}
	return "<address>", "Find this server's address, for <address> below: it's what " + b.Hostname + " resolves to (for example, with nslookup " + b.Hostname + ")."
}

// withFind prepends find, if it's set, to steps.
func withFind(find string, steps ...string) []string {
	if find == "" {
		return steps
	}
	return append([]string{find}, steps...)
}

// as is " as <device>", if the device is named.
func (b *platformBuilder) as() string {
	if b.Device == "" {
		return ""
	}
	return " as " + b.Device
}

// identifiedBy says how doh knows a device that names the profile in its
// settings: by what (the DoH URL or the DoT host name).
func (b *platformBuilder) identifiedBy(what string) string {
	if b.Device != "" {
		return "By the device name in its " + what + ": doh shows it as " + b.Device + ", with profile " + b.Profile + ", on any network."
	}
	return "By the profile in its " + what + ", on any network: doh uses profile " + b.Profile + ". Name the device when you make these settings, so the log can tell it apart from others."
}

// identifiedEncrypted is identifiedBy for the preferred protocol.
func (b *platformBuilder) identifiedEncrypted() string {
	if b.DoHURL != "" {
		return b.identifiedBy("DNS-over-HTTPS URL")
	}
	return b.identifiedBy("DNS-over-TLS host name")
}

// identifiedPlain says how doh knows a device over plain DNS.
func (b *platformBuilder) identifiedPlain() string {
	s := "By its address, since plain DNS carries no name. "
	switch {
	case b.isDefault:
		s += "Devices whose addresses no profile lists get this one, the default profile; to give one other rules, add its address to another profile's devices."
	case b.listed:
		s += "This profile gets the addresses in its devices and clients: add the device's address there if it isn't."
	default:
		s += "Add the device's address to this profile's devices (or its network to the profile's clients), or it gets the default profile."
	}
	return s + " Give it a DHCP reservation (a fixed address) in your router, so its address doesn't change. doh also learns the names devices give themselves on the network, for the log."
}

// check says how to see a device's queries arrive.
func (b *platformBuilder) check() string {
	return "Open any website on the device, then look in doh's Activity view: its lookups appear with profile " + b.Profile + b.as() + "."
}

// checkPlain says how to see a plain DNS device's queries arrive.
func (b *platformBuilder) checkPlain() string {
	return "Open any app or website on the device, then look for its address in doh's Activity view, with the profile it matched. From a computer on the same network, dig CH TXT id.server @" + b.dnsAddr() + " shows the profile that computer's own lookups match."
}

// Notes shared by several platforms.
const (
	plainNote     = "Plain DNS isn't encrypted on your network: anyone on it could see, or change, the device's lookups."
	hardCodedNote = "Some devices use DNS servers built into them (such as 8.8.8.8), whatever the network says, and skip doh. Only a router or firewall that redirects DNS (port 53) to doh catches those. Turn on this profile's bypass protection too: it blocks well-known public encrypted DNS services that apps could switch to."
	unsignedNote  = "If the profile shows as unverified, it isn't signed; the settings work the same."
	portalNote    = "Captive Wi-Fi sign-in pages (hotels, planes) may not load while the encrypted server can't be reached, and a profile can't make an exception for them: if one won't load, remove the profile until you're signed in, then install it again."
	lockNote      = "The locked version also stops people turning the DNS setting off (ProhibitDisablement), on supervised devices only; other devices ignore it."
	relayNote     = "iCloud Private Relay, when on, resolves Safari's names itself, around doh. With this profile's bypass protection on, doh answers Private Relay's check the way networks that don't allow it do."
)

// unavailableStep explains that devices needing plain DNS can't use this
// server.
func (b *platformBuilder) unavailableStep() string {
	if b.tenant {
		return "These devices only use plain DNS on your own network, which this server doesn't serve. Ask this server's operator about a doh server for your network."
	}
	return "These devices only use plain DNS on your own network, which this server doesn't serve. Run doh on your network with --dns-listen :53 (it can follow this server's policy with --policy) and point them at that."
}

// routerStep is the first step for devices best set up at the router.
func (b *platformBuilder) routerStep(what string) string {
	return "Best: set your router to hand out " + b.dnsAddrs() + " as the DNS server (see Whole network), and give " + what + " a DHCP reservation so its address stays the same."
}

// profileNote is what to say about configuration profiles' signatures:
// the signer's note when there is one, or else nothing if they're signed.
func (b *platformBuilder) profileNote() []string {
	switch {
	case b.signing == nil:
		return []string{unsignedNote}
	case b.signing.Note != "":
		return []string{b.signing.Note}
	}
	return nil
}

// mobileConfigs offers Apple configuration profiles on p, and says
// whether they're signed.
func (b *platformBuilder) mobileConfigs(p *api.Platform) {
	p.Signing = b.signing
	filename := b.Profile
	if b.Device != "" {
		filename += "-" + b.Device
	}
	filename += ".mobileconfig"
	if b.DoHURL != "" {
		b.download(p, "Configuration profile", mobileConfigFile, filename, api.MobileConfigType, nil)
	}
	if b.DoTHost != "" {
		name := "Configuration profile"
		if b.DoHURL != "" {
			name += " (DNS-over-TLS)"
		}
		b.download(p, name, mobileConfigFile, filename, api.MobileConfigType, url.Values{"protocol": {"tls"}})
	}
	q := url.Values{"lock": {"true"}}
	if b.DoHURL == "" {
		q.Set("protocol", "tls")
	}
	b.download(p, "Configuration profile, locked (supervised devices)", mobileConfigFile, filename, api.MobileConfigType, q)
}

func (b *platformBuilder) apple() {
	if b.DoHURL == "" && b.DoTHost == "" {
		return
	}
	p := b.add("apple", api.GroupPhones, "iPhone and iPad", b.encrypted("on every network, Wi-Fi and cellular"),
		"On the iPhone or iPad, open the setup link in Safari, or download the configuration profile there (or AirDrop it from a Mac), and tap Allow.",
		"Open Settings and tap Profile Downloaded near the top (or find it under General, then VPN & Device Management), then tap Install.",
		"To stop, remove the profile from General, then VPN & Device Management.",
	)
	b.mobileConfigs(p)
	p.Check, p.Identified = b.check(), b.identifiedEncrypted()
	p.Notes = slices.Concat([]string{"Needs iOS or iPadOS 14 or later."}, b.profileNote(), []string{portalNote, lockNote, relayNote})
}

func (b *platformBuilder) visionPro() {
	if b.DoHURL == "" && b.DoTHost == "" {
		return
	}
	p := b.add("vision-pro", api.GroupPhones, "Apple Vision Pro", b.encrypted("on every network"),
		"On Apple Vision Pro, open the setup link in Safari, or download the configuration profile there, and allow the download.",
		"Open Settings and install the downloaded profile, as on an iPhone or iPad.",
		"To stop, remove the profile in Settings.",
	)
	b.mobileConfigs(p)
	p.Check, p.Identified = b.check(), b.identifiedEncrypted()
	p.Notes = append([]string{"Apple supports configuration profiles on visionOS 1.1 and later. doh hasn't been tried on one, so check the Activity view after installing."}, b.profileNote()...)
}

func (b *platformBuilder) android() {
	switch {
	case b.DoTHost != "":
		p := b.add("android", api.GroupPhones, "Android phones and tablets",
			api.Protection{Level: api.ProtectionEncrypted, Protocol: "tls", Summary: "Encrypted on every network, Wi-Fi and mobile data, with Private DNS (DNS-over-TLS)."},
			"Open Settings, then Network & internet (or Connections), then Private DNS.",
			"Choose Private DNS provider hostname, enter "+b.DoTHost+", and save.",
		)
		if b.dotPort != "853" {
			p.Steps = append(p.Steps, "Android only connects on port 853, so make sure this server's DoT listener is reachable there.")
		}
		p.Check = "Private DNS shows the host name; if Android can't reach it, it says so there, and the network may show as having no internet. " + b.check()
		p.Identified = b.identifiedBy("Private DNS host name")
		p.Notes = []string{
			"Needs Android 9 or later. The setting's place varies by maker; search Settings for Private DNS.",
			"Apps with their own secure DNS setting, such as Chrome set to another provider, can go around it.",
		}
	case b.DoHURL != "":
		p := b.add("android", api.GroupPhones, "Android phones and tablets",
			api.Protection{Level: api.ProtectionEncrypted, Protocol: "https", Summary: "Only Chrome is encrypted: Android's own Private DNS needs DNS-over-TLS, which this server doesn't serve."},
			"In Chrome, open Settings, then Privacy and security, then Use secure DNS, choose another provider, and enter "+b.DoHURL+".",
		)
		if len(b.DNSAddrs) > 0 {
			p.Steps = append(p.Steps, "For the rest of the device, on your own Wi-Fi, use plain DNS from your router (see Whole network).")
		}
		p.Check, p.Identified = b.check(), b.identifiedBy("DNS-over-HTTPS URL")
	case len(b.DNSAddrs) > 0:
		p := b.add("android", api.GroupPhones, "Android phones and tablets",
			plainDNS("Plain DNS on your own Wi-Fi only: Private DNS needs DNS-over-TLS, which this server doesn't serve."),
			b.routerStep("the device"),
			"Or on the device: in the Wi-Fi network's settings, change IP settings to Static and enter "+b.dnsAddr()+" as DNS 1. Static also needs the device's own address, gateway, and prefix length.",
		)
		p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote}
	}
}

func (b *platformBuilder) mac() {
	if b.DoHURL == "" && b.DoTHost == "" {
		return
	}
	p := b.add("mac", api.GroupComputers, "Mac", b.encrypted("on every network"),
		"Download the configuration profile on the Mac (or AirDrop it there), and open it.",
		"Open System Settings and install it where macOS lists downloaded profiles: General, then Device Management on macOS 15; Privacy & Security, then Profiles on macOS 13 and 14.",
		"To stop, remove it from the same place.",
	)
	b.mobileConfigs(p)
	p.Check, p.Identified = b.check(), b.identifiedEncrypted()
	p.Notes = slices.Concat([]string{"Needs macOS 11 or later."}, b.profileNote(), []string{relayNote,
		"Browsers set to their own secure DNS provider skip it: set them to use the system's settings (or this server, under Browsers).",
	})
}

func (b *platformBuilder) windows() {
	switch {
	case b.DoHURL != "":
		addr := cmp.Or(b.serverAddr(), b.Hostname+"'s address (what it resolves to; the script looks it up for you)")
		p := b.add("windows", api.GroupComputers, "Windows",
			api.Protection{Level: api.ProtectionEncrypted, Protocol: "https", Summary: "Encrypted with Windows 11's built-in DNS over HTTPS, with no fallback to plain DNS."},
			"Download "+devicesetup.WindowsFile+" and read it: it changes only this PC's DNS settings, explains each line, and fetches nothing.",
			"Open PowerShell as administrator in the folder you saved it to, and preview what it would change: powershell -ExecutionPolicy Bypass -File .\\"+devicesetup.WindowsFile+" -WhatIf",
			"Run the same without -WhatIf to apply it. Running it with -Revert undoes it.",
			"Or by hand: open Settings, then Network & internet, then your connection (Wi-Fi or Ethernet), then DNS server assignment: Edit. Choose Manual, turn on IPv4, enter "+addr+" as Preferred DNS, set DNS over HTTPS to On (manual template), and enter "+b.DoHURL+".",
		)
		b.download(p, "PowerShell setup script", devicesetup.WindowsFile, devicesetup.WindowsFile, api.TextFileType, nil)
		p.Check = "The connection's properties in Settings list the DNS server as encrypted. " + b.check()
		p.Identified = b.identifiedBy("DNS-over-HTTPS URL")
		p.Notes = []string{
			"Windows 10 has no built-in DNS over HTTPS: there, use a browser's secure DNS (see Browsers), and plain DNS for the rest.",
			"With no fallback, if doh can't be reached, lookups fail rather than go unencrypted.",
			"A VPN can set its own DNS servers while it's connected.",
		}
	case len(b.DNSAddrs) > 0:
		p := b.add("windows", api.GroupComputers, "Windows",
			plainDNS("Plain DNS on your own network: encrypted settings need this server's DNS-over-HTTPS, which it doesn't serve."),
			"Open Settings, then Network & internet, then your connection (Wi-Fi or Ethernet), then DNS server assignment: Edit.",
			"Choose Manual, turn on IPv4, and enter "+b.dnsAddr()+" as Preferred DNS, leaving Alternate DNS empty.",
		)
		p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote}
	}
}

func (b *platformBuilder) linux() {
	switch {
	case b.DoTHost != "":
		p := b.add("linux", api.GroupComputers, "Linux",
			api.Protection{Level: api.ProtectionEncrypted, Protocol: "tls", Summary: "Encrypted with systemd-resolved's DNS-over-TLS, with no fallback to plain DNS."},
		)
		if len(b.ServerAddrs) > 0 {
			b.download(p, "systemd-resolved drop-in", devicesetup.ResolvedFile, devicesetup.ResolvedFile, api.TextFileType, nil)
			p.Steps = append(p.Steps, "Download "+devicesetup.ResolvedFile+", then install it: sudo mkdir -p /etc/systemd/resolved.conf.d, then sudo cp "+devicesetup.ResolvedFile+" "+devicesetup.ResolvedPath+".")
		} else {
			addr, find := b.serverAddrOr()
			p.Steps = withFind(find, "Create "+devicesetup.ResolvedPath+" with a [Resolve] section of DNS="+addr+"#"+b.DoTHost+", DNSOverTLS=yes, and Domains=~.")
		}
		p.Steps = append(p.Steps,
			"Run sudo systemctl restart systemd-resolved.",
			"NetworkManager passes each network's own DNS servers on to systemd-resolved; the drop-in's Domains=~. puts doh first for every name. Where /etc/resolv.conf doesn't point at systemd-resolved (127.0.0.53), it isn't used: set your browser's secure DNS instead (see Browsers).",
		)
		p.Check = "resolvectl status shows +DNSOverTLS, and doh under Global. " + b.check()
		p.Identified = b.identifiedBy("DNS-over-TLS host name")
		p.Notes = []string{"To undo, delete " + devicesetup.ResolvedPath + " and restart systemd-resolved."}
	case len(b.DNSAddrs) > 0:
		p := b.add("linux", api.GroupComputers, "Linux",
			plainDNS("Plain DNS on your own network: encrypted settings need this server's DNS-over-TLS, which it doesn't serve."),
			"With NetworkManager: nmcli connection modify <connection> ipv4.dns "+b.dnsAddr()+" ipv4.ignore-auto-dns yes, then nmcli connection up <connection>.",
		)
		if b.DoHURL != "" {
			p.Steps = append(p.Steps, "Browsers can still use DNS-over-HTTPS (see Browsers).")
		}
		p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote}
	}
}

func (b *platformBuilder) chromeOS() {
	switch {
	case b.DoHURL != "":
		p := b.add("chromeos", api.GroupComputers, "Chromebook", b.encrypted("on every network"),
			"Open Settings, find Use secure DNS (under privacy and security), and turn it on.",
			"Choose a custom provider, and enter "+b.DoHURL+".",
		)
		p.Check, p.Identified = b.check(), b.identifiedBy("DNS-over-HTTPS URL")
		p.Notes = []string{
			"On a school or work Chromebook, an administrator may set this for you.",
			"Android apps and the Linux development environment on a Chromebook may look names up on their own.",
		}
	case len(b.DNSAddrs) > 0:
		p := b.add("chromeos", api.GroupComputers, "Chromebook",
			plainDNS("Plain DNS on your own network: ChromeOS's secure DNS needs this server's DNS-over-HTTPS, which it doesn't serve."),
			"Open Settings, then Network, choose your Wi-Fi network, and under Network set the name servers to custom: "+b.dnsAddr()+".",
		)
		p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote}
	}
}

func (b *platformBuilder) appleTV() {
	if b.DoHURL == "" && b.DoTHost == "" {
		return
	}
	p := b.add("apple-tv", api.GroupTV, "Apple TV",
		api.Protection{Level: api.ProtectionEncrypted, Protocol: b.encrypted("").Protocol, Summary: "Encrypted, once installed with Apple Configurator or device management (MDM): Apple TV doesn't install profiles from a download."},
		"Download the configuration profile on a Mac.",
		"Install it on the Apple TV with Apple Configurator on that Mac (with the Apple TV paired to it), or through your device management (MDM) service.",
	)
	if len(b.DNSAddrs) > 0 {
		p.Steps = append(p.Steps, "Without either, set its DNS by address instead: in the Apple TV's network settings, configure DNS manually with "+b.dnsAddr()+" (plain DNS, as for other TVs).")
	}
	b.mobileConfigs(p)
	p.Check, p.Identified = b.check(), b.identifiedEncrypted()
	p.Notes = []string{"doh hasn't been tried on an Apple TV, so check the Activity view after installing; if its lookups don't appear, set its DNS by address instead."}
}

func (b *platformBuilder) androidTV() {
	switch {
	case b.DoTHost != "":
		p := b.add("android-tv", api.GroupTV, "Android TV and Google TV",
			api.Protection{Level: api.ProtectionEncrypted, Protocol: "tls", Summary: "Encrypted with Private DNS (DNS-over-TLS) where the TV has it, from Android TV 9 on; many TVs hide the setting."},
			"If the TV's network settings offer Private DNS, choose the provider host name option and enter "+b.DoTHost+".",
			"If they don't, a computer with adb can set it: turn on the TV's developer options and USB or network debugging, connect with adb, then run adb shell settings put global private_dns_mode hostname, and adb shell settings put global private_dns_specifier "+b.DoTHost+".",
		)
		if len(b.DNSAddrs) > 0 {
			p.Steps = append(p.Steps, "Otherwise, use plain DNS by address: set it on your router (see Whole network), or in the TV's network settings.")
		}
		p.Check, p.Identified = b.check(), b.identifiedBy("Private DNS host name")
		p.Notes = []string{
			"To undo the adb setting, run adb shell settings put global private_dns_mode opportunistic.",
			"TV makers change these menus, and some Android-based devices, such as Fire TV, may not keep the setting.",
			"Android only connects on port 853.",
		}
	case len(b.DNSAddrs) > 0:
		p := b.add("android-tv", api.GroupTV, "Android TV and Google TV",
			plainDNS("Plain DNS on your own network: Private DNS needs DNS-over-TLS, which this server doesn't serve."),
			b.routerStep("the TV"),
			"Or in the TV's network settings, set a static IP with "+b.dnsAddr()+" as its DNS.",
		)
		p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote, hardCodedNote}
	}
}

func (b *platformBuilder) smartTV() {
	const name = "Smart TVs and streaming sticks"
	if len(b.DNSAddrs) == 0 {
		b.add("smart-tv", api.GroupTV, name, unavailable("Needs plain DNS on your own network, which this server doesn't serve."), b.unavailableStep())
		return
	}
	p := b.add("smart-tv", api.GroupTV, name,
		plainDNS("Plain DNS by address: these devices have no encrypted DNS setting of their own."),
		b.routerStep("the TV or stick"),
		"Or on the device: Samsung and LG TVs, and Fire TV, can take a DNS server by hand in their network settings (often under IP or advanced settings): enter "+b.dnsAddr()+".",
		"Roku and Chromecast have no DNS setting: only the router can point them at doh.",
	)
	p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote, hardCodedNote}
}

func (b *platformBuilder) consoles() {
	const name = "PlayStation, Xbox, and Nintendo Switch"
	if len(b.DNSAddrs) == 0 {
		b.add("consoles", api.GroupConsoles, name, unavailable("Needs plain DNS on your own network, which this server doesn't serve."), b.unavailableStep())
		return
	}
	p := b.add("consoles", api.GroupConsoles, name,
		plainDNS("Plain DNS by address: consoles have no encrypted DNS setting."),
		b.routerStep("the console"),
		"Or on the console, set DNS to manual with "+b.dnsAddr()+" as the primary DNS. PlayStation: in Settings, Network, set the connection up again with advanced settings. Xbox: Settings, General, Network settings, Advanced settings, DNS settings. Nintendo Switch: System Settings, Internet, Internet Settings, choose the network, then Change Settings, DNS Settings.",
		"Leave the secondary DNS empty, or if it must be set, use doh's address again: a public server there, such as 8.8.8.8, lets the console skip doh.",
	)
	p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote}
}

func (b *platformBuilder) smartHome() {
	const name = "Smart speakers and other smart devices"
	if len(b.DNSAddrs) == 0 {
		b.add("smart-home", api.GroupSmartHome, name, unavailable("Needs plain DNS on your own network, which this server doesn't serve."), b.unavailableStep())
		return
	}
	p := b.add("smart-home", api.GroupSmartHome, name,
		plainDNS("Plain DNS by address, set at the router: these devices have no DNS settings."),
		"Set your router to hand out "+b.dnsAddrs()+" as the DNS server (see Whole network).",
		"Give each device a DHCP reservation, and add the ones that need their own rules to a profile's devices, so doh knows which is asking.",
	)
	p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote, hardCodedNote}
}

func (b *platformBuilder) browsers() {
	if b.DoHURL == "" {
		return
	}
	p := b.add("browser", api.GroupBrowsers, "Chrome, Edge, Brave, and Firefox",
		api.Protection{Level: api.ProtectionEncrypted, Protocol: "https", Summary: "Encrypted for that browser only, with DNS-over-HTTPS; the rest of the device uses its own settings."},
		"Chrome and Brave: Settings, then Privacy and security, then Security, then Use secure DNS: choose a custom provider and enter "+b.DoHURL+".",
		"Edge: Settings, then Privacy, search, and services, then Use secure DNS: choose a service provider and enter "+b.DoHURL+".",
		"Firefox: Settings, then Privacy & Security, then DNS over HTTPS: choose Max Protection, set the provider to Custom, and enter "+b.DoHURL+".",
		"Safari uses the device's own settings: set up the device instead.",
	)
	p.Check, p.Identified = b.check(), b.identifiedBy("DNS-over-HTTPS URL")
	p.Notes = []string{
		"Firefox turns on its own DNS over HTTPS in some countries unless the network says not to. doh answers Firefox's canary domain so it keeps using the network's resolver; a browser set to another provider still skips doh.",
		"Work or school browsers may have this set by policy.",
	}
}

func (b *platformBuilder) router() {
	const name = "Any router"
	if len(b.DNSAddrs) == 0 {
		b.add("router", api.GroupNetwork, name, unavailable("Needs plain DNS on your own network, which this server doesn't serve."), b.unavailableStep())
		return
	}
	p := b.add("router", api.GroupNetwork, name,
		plainDNS("Plain DNS on your network, each device by its address: covers devices with no settings of their own."),
		"Open your router's admin page or app, and find the DNS server it hands out over DHCP (often under LAN or DHCP settings).",
		"Set it to "+b.dnsAddrs()+". Leave the secondary empty, or set it to another of doh's addresses, never a public server such as 8.8.8.8, which devices would use to skip doh.",
		"Reconnect devices, or restart them, so they pick up the change.",
	)
	if !b.listed && !b.isDefault {
		p.Steps = append(p.Steps, "Over plain DNS, devices are matched to profiles by address: add the device's address to this profile's devices or clients.")
	}
	p.Check, p.Identified = b.checkPlain(), b.identifiedPlain()
	p.Notes = []string{
		"Some routers only let you change their own upstream (WAN or internet) DNS, not what DHCP hands out. That works too, but doh then sees every device as the router, under one profile.",
		hardCodedNote, plainNote,
	}
}

func (b *platformBuilder) openWrt() {
	if len(b.DNSAddrs) == 0 {
		return
	}
	p := b.add("openwrt", api.GroupNetwork, "OpenWrt",
		plainDNS("Plain DNS on your network, each device by its address, handed out by the router."),
		"Download "+devicesetup.OpenWrtFile+" and read it: with uci, it hands out "+b.dnsAddrs()+" over DHCP, and forwards the router's own resolver (dnsmasq) to doh.",
		"Copy it to the router and run it there: scp -O "+devicesetup.OpenWrtFile+" root@192.168.1.1:/tmp/, then ssh root@192.168.1.1 sh /tmp/"+devicesetup.OpenWrtFile+", using your router's address. Run it with revert to undo it.",
		"Or in LuCI: Network, then Interfaces, edit LAN, then DHCP Server, then Advanced Settings, and add the DHCP option 6,"+b.dnsAddr()+".",
	)
	b.download(p, "OpenWrt setup script", devicesetup.OpenWrtFile, devicesetup.OpenWrtFile, api.TextFileType, nil)
	p.Check, p.Identified = b.checkPlain(), b.identifiedPlain()
	p.Notes = []string{
		"If doh itself forwards lookups to this router, leave out the script's dnsmasq lines, or lookups loop between the two.",
		"OpenWrt's firewall can also redirect DNS (port 53) to the router, catching devices with built-in DNS servers; doh sees those as the router.",
		plainNote,
	}
}

func (b *platformBuilder) pfSense() {
	const name = "pfSense and OPNsense"
	dhcp := "Hand out " + b.dnsAddrs() + " as the DNS server in the DHCP server's settings for your LAN, so devices ask doh directly and doh tells them apart by address."
	switch {
	case b.DoTHost != "":
		addr, find := b.serverAddrOr()
		p := b.add("pfsense", api.GroupNetwork, name,
			api.Protection{Level: api.ProtectionEncrypted, Protocol: "tls", Summary: "Encrypted from the firewall to doh with DNS-over-TLS; devices' lookups to the firewall stay plain on your network, and doh sees them all as the firewall."},
			withFind(find,
				"Forward the firewall's resolver (Unbound) to doh over DNS-over-TLS, with "+addr+", port 853, and "+b.DoTHost+" as the TLS host name. pfSense: in the DNS Resolver, turn on forwarding mode and SSL/TLS for outgoing queries, and add the server, with its TLS host name, under System, General Setup. OPNsense: add it as a DNS-over-TLS server in Unbound DNS's settings.",
				"In Unbound's own terms, that's a forward-zone for \".\" with forward-tls-upstream: yes and forward-addr: "+addr+"@853#"+b.DoTHost+".",
			)...,
		)
		if len(b.DNSAddrs) > 0 {
			p.Steps = append(p.Steps, "Or, to keep devices apart in doh: "+dhcp)
		}
		p.Check = "Look in doh's Activity view for lookups from the firewall, with profile " + b.Profile + b.as() + "."
		p.Identified = "As the firewall, by the profile in the DNS-over-TLS host name: every device behind it gets profile " + b.Profile + "."
		p.Notes = []string{"Menu names differ between versions; the settings to find are forwarding, DNS-over-TLS (SSL/TLS), the server's address, and its TLS host name."}
	case len(b.DNSAddrs) > 0:
		p := b.add("pfsense", api.GroupNetwork, name,
			plainDNS("Plain DNS on your network, each device by its address, handed out by the firewall's DHCP server."),
			dhcp,
			"Reconnect devices so they pick up the change.",
		)
		p.Check, p.Identified, p.Notes = b.checkPlain(), b.identifiedPlain(), []string{plainNote}
	}
}

func (b *platformBuilder) unifi() {
	if len(b.DNSAddrs) == 0 {
		return
	}
	p := b.add("unifi", api.GroupNetwork, "UniFi",
		plainDNS("Plain DNS on your network, each device by its address, handed out by the UniFi gateway."),
		"In the UniFi Network application, open Settings, then Networks, and choose the network.",
		"Under DHCP, set the DNS server to manual (not Auto), and enter "+b.dnsAddrs()+".",
		"Reconnect devices so they pick up the change.",
	)
	p.Check, p.Identified = b.checkPlain(), b.identifiedPlain()
	p.Notes = []string{plainNote, hardCodedNote}
}
