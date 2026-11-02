package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
)

// testSetup is a setup for a server with every way to connect.
var testSetup = api.Setup{
	Profile:  "kids",
	Device:   "tablet",
	Hostname: "dns.example.com",
	DoHURL:   "https://dns.example.com/dns-query/kids/tablet",
	DoTHost:  "tablet--kids.dns.example.com",
	DNSAddrs: []string{"192.168.1.10"},
	Platforms: []api.Platform{
		{ID: "apple", Name: "iPhone, iPad, and Mac", Steps: []string{"Download the configuration profile below on the device, or AirDrop it there."}, Download: "/api/v1/profiles/kids/apple.mobileconfig?device=tablet"},
		{ID: "android", Name: "Android", Steps: []string{"Open Settings, then Network & internet, then Private DNS.", "Choose Private DNS provider hostname, enter tablet--kids.dns.example.com, and save."}},
		{ID: "router", Name: "Your whole network", Steps: []string{"Set your router's DHCP DNS server to 192.168.1.10."}},
	},
}

func TestSetupCommand(t *testing.T) {
	out, f, err := runClient(t, newSetupCommand(), map[string]any{
		"GET /api/v1/profiles/kids/setup": testSetup,
	}, "setup", "kids", "--device", "tablet")
	if err != nil {
		t.Fatal(err)
	}
	if f.requests[0] != "GET /api/v1/profiles/kids/setup?device=tablet" {
		t.Errorf("requested %v", f.requests)
	}

	for _, want := range []string{
		"Connect a device to profile kids as tablet",
		"DNS-over-HTTPS  https://dns.example.com/dns-query/kids/tablet",
		"DNS-over-TLS    tablet--kids.dns.example.com",
		"Plain DNS       192.168.1.10",
		"\nAndroid\n  1. Open Settings",
		"  2. Choose Private DNS provider hostname, enter tablet--kids.dns.example.com,",
		"doh setup kids --device tablet --mobileconfig kids-tablet.mobileconfig",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > setupWidth && !strings.Contains(line, "https://") {
			t.Errorf("line longer than %d: %q", setupWidth, line)
		}
	}
}

func TestSetupCommand_Platform(t *testing.T) {
	responses := map[string]any{"GET /api/v1/profiles/kids/setup": testSetup}

	out, _, err := runClient(t, newSetupCommand(), responses, "setup", "kids", "--platform", "android")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Android") || strings.Contains(out, "iPhone") || strings.Contains(out, "Your whole network") {
		t.Errorf("--platform android shows other platforms:\n%s", out)
	}

	_, _, err = runClient(t, newSetupCommand(), responses, "setup", "kids", "--platform", "windows")
	if err == nil || !strings.Contains(err.Error(), "apple, android, router") {
		t.Errorf("unknown platform: %v, want the available ones listed", err)
	}
}

func TestSetupCommand_JSON(t *testing.T) {
	out, _, err := runClient(t, newSetupCommand(), map[string]any{
		"GET /api/v1/profiles/kids/setup": testSetup,
	}, "setup", "kids", "--json", "--platform", "router")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"doh_url": "https://dns.example.com/dns-query/kids/tablet"`) || strings.Contains(out, `"android"`) {
		t.Errorf("JSON output:\n%s", out)
	}
}

func TestSetupCommand_NothingToSetUp(t *testing.T) {
	out, _, err := runClient(t, newSetupCommand(), map[string]any{
		"GET /api/v1/profiles/default/setup": api.Setup{Profile: "default", Platforms: []api.Platform{
			{ID: "none", Name: "Nothing to set up yet", Steps: []string{"Set --hostname to this server's public name."}},
		}},
	}, "setup", "default")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Nothing to set up yet\n  1. Set --hostname") {
		t.Errorf("output:\n%s", out)
	}
}

func TestSetupCommand_MobileConfig(t *testing.T) {
	const plist = "<plist version=\"1.0\"><dict/></plist>\n"
	responses := map[string]any{"GET /api/v1/profiles/kids/apple.mobileconfig": []byte(plist)}

	path := filepath.Join(t.TempDir(), "ipad.mobileconfig")
	out, f, err := runClient(t, newSetupCommand(), responses, "setup", "kids", "--device", "ipad", "--protocol", "tls", "--mobileconfig", path)
	if err != nil {
		t.Fatal(err)
	}
	if f.requests[0] != "GET /api/v1/profiles/kids/apple.mobileconfig?device=ipad&protocol=tls" {
		t.Errorf("requested %v", f.requests)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != plist {
		t.Fatalf("wrote %q, %v", b, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want 0644", info.Mode().Perm())
	}
	if !strings.Contains(out, "Wrote "+path) || !strings.Contains(out, "Profile Downloaded") {
		t.Errorf("output:\n%s", out)
	}

	// "-" writes only the configuration profile, for redirecting.
	out, _, err = runClient(t, newSetupCommand(), responses, "setup", "kids", "--mobileconfig", "-")
	if err != nil || out != plist {
		t.Errorf("--mobileconfig - = %q, %v", out, err)
	}
}

func TestSetupCommand_RejectsBadFlags(t *testing.T) {
	for _, args := range [][]string{
		{"setup", "kids", "--protocol", "ftp", "--mobileconfig", "-"},
		{"setup", "kids", "--protocol", "tls"}, // only with --mobileconfig
		{"setup"},
	} {
		if _, f, err := runClient(t, newSetupCommand(), nil, args...); err == nil || len(f.requests) != 0 {
			t.Errorf("%v: err %v, requests %v; want an error before any request", args, err, f.requests)
		}
	}
}

func TestWrap(t *testing.T) {
	for _, tt := range []struct {
		in    string
		width int
		want  string
	}{
		{"a b c", 80, "a b c"},
		{"one two three", 7, "one two\n  three"},
		{"https://a-very-long-url.example/path ok", 10, "https://a-very-long-url.example/path\n  ok"},
		{"  spaced   out  ", 80, "spaced out"},
		{"", 80, ""},
	} {
		if got := wrap(tt.in, tt.width, "  "); got != tt.want {
			t.Errorf("wrap(%q, %d) = %q, want %q", tt.in, tt.width, got, tt.want)
		}
	}
}

func TestSetupCommand_Link(t *testing.T) {
	link := api.SetupLink{URL: "https://dns.example.com/setup/RfcDwNWF3WMikylWanaHcg", Expires: time.Now().Add(30 * time.Minute)}
	responses := map[string]any{"POST /api/v1/profiles/kids/setup-links": link}

	out, f, err := runClient(t, newSetupCommand(), responses, "setup", "kids", "--device", "ipad", "--link")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.requests[0]; got != "POST /api/v1/profiles/kids/setup-links?device=ipad" {
		t.Errorf("request = %q", got)
	}
	if !strings.Contains(out, link.URL) || !strings.Contains(out, "scan it with its camera") || !strings.Contains(out, "▀") {
		t.Errorf("output lacks the link, its explanation, or a QR code:\n%s", out)
	}

	for _, args := range [][]string{{"--mobileconfig", "x.mobileconfig"}, {"--platform", "apple"}} {
		if _, _, err := runClient(t, newSetupCommand(), responses, append([]string{"setup", "kids", "--link"}, args...)...); err == nil {
			t.Errorf("--link with %v was accepted", args)
		}
	}
}

// groupedSetup is a setup as servers describe it now: grouped, with
// protection levels and downloads.
var groupedSetup = api.Setup{
	Profile:  "kids",
	Device:   "laptop",
	Hostname: "dns.example.com",
	DoHURL:   "https://dns.example.com/dns-query/kids/laptop",
	DoTHost:  "laptop--kids.dns.example.com",
	DNSAddrs: []string{"192.168.1.10"},
	Groups: []api.PlatformGroup{
		{ID: api.GroupComputers, Name: "Computers"},
		{ID: api.GroupTV, Name: "TV & streaming"},
	},
	Platforms: []api.Platform{
		{
			ID: "windows", Group: api.GroupComputers, Name: "Windows",
			Protection: &api.Protection{Level: api.ProtectionEncrypted, Protocol: "https", Summary: "Encrypted with Windows 11's built-in DNS over HTTPS."},
			Steps:      []string{"Download doh-setup.ps1 and read it."},
			Download:   "/api/v1/profiles/kids/doh-setup.ps1?device=laptop",
			Downloads:  []api.Download{{Name: "PowerShell setup script", File: "doh-setup.ps1", Path: "/api/v1/profiles/kids/doh-setup.ps1?device=laptop", ContentType: api.TextFileType}},
			Check:      "Look in doh's Activity view.",
			Identified: "By the device name in its DNS-over-HTTPS URL.",
			Notes:      []string{"Windows 10 has no built-in DNS over HTTPS."},
		},
		{
			ID: "mac", Group: api.GroupComputers, Name: "Mac",
			Protection: &api.Protection{Level: api.ProtectionEncrypted, Protocol: "https", Summary: "Encrypted."},
			Steps:      []string{"Open it."},
			Download:   "/api/v1/profiles/kids/apple.mobileconfig?device=laptop",
			Downloads: []api.Download{
				{Name: "Configuration profile", File: "kids-laptop.mobileconfig", Path: "/api/v1/profiles/kids/apple.mobileconfig?device=laptop", ContentType: api.MobileConfigType},
				{Name: "Configuration profile (DNS-over-TLS)", File: "kids-laptop.mobileconfig", Path: "/api/v1/profiles/kids/apple.mobileconfig?device=laptop&protocol=tls", ContentType: api.MobileConfigType},
				{Name: "Configuration profile, locked (supervised devices)", File: "kids-laptop.mobileconfig", Path: "/api/v1/profiles/kids/apple.mobileconfig?device=laptop&lock=true", ContentType: api.MobileConfigType},
			},
		},
		{
			ID: "smart-tv", Group: api.GroupTV, Name: "Smart TVs and streaming sticks",
			Protection: &api.Protection{Level: api.ProtectionPlain, Protocol: "dns", Summary: "Plain DNS by address."},
			Steps:      []string{"Set your router to hand out 192.168.1.10."},
			Identified: "By its address.",
		},
	},
}

func TestSetupCommand_Grouped(t *testing.T) {
	out, _, err := runClient(t, newSetupCommand(), map[string]any{"GET /api/v1/profiles/kids/setup": groupedSetup}, "setup", "kids", "--device", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\nCOMPUTERS\n=========\n",
		"\nWindows (encrypted, DoH)\n  Encrypted with Windows 11's built-in DNS over HTTPS.\n  1. Download doh-setup.ps1",
		"doh setup kids --device laptop --platform windows --download doh-setup.ps1",
		"(other versions: --protocol tls, --lock)",
		"  Check: Look in doh's Activity view.",
		"  How doh knows it: By the device name",
		"  - Windows 10 has no built-in DNS over HTTPS.",
		"\nTV & STREAMING\n",
		"Smart TVs and streaming sticks (plain DNS)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		// URLs and commands to copy stay whole.
		if len(line) > setupWidth && !strings.Contains(line, "https://") && !strings.HasPrefix(line, "    doh setup ") {
			t.Errorf("line longer than %d: %q", setupWidth, line)
		}
	}
}

func TestSetupCommand_PlatformGroupAndList(t *testing.T) {
	responses := map[string]any{"GET /api/v1/profiles/kids/setup": groupedSetup}

	out, _, err := runClient(t, newSetupCommand(), responses, "setup", "kids", "--platform", "computers")
	if err != nil || !strings.Contains(out, "Windows") || !strings.Contains(out, "Mac") || strings.Contains(out, "Smart TVs") {
		t.Errorf("--platform computers = %v:\n%s", err, out)
	}

	out, _, err = runClient(t, newSetupCommand(), responses, "setup", "kids", "--list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"PLATFORM  GROUP           PROTECTION      NAME",
		"windows   Computers       encrypted, DoH  Windows",
		"smart-tv  TV & streaming  plain DNS       Smart TVs and streaming sticks",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--list lacks %q:\n%s", want, out)
		}
	}

	_, _, err = runClient(t, newSetupCommand(), responses, "setup", "kids", "--platform", "consoles")
	if err == nil || !strings.Contains(err.Error(), "windows, mac, smart-tv, computers, tv") {
		t.Errorf("unknown platform: %v, want platforms and groups listed", err)
	}
}

func TestSetupCommand_Download(t *testing.T) {
	const script = "<# a script #>\n"
	responses := map[string]any{
		"GET /api/v1/profiles/kids/setup":              groupedSetup,
		"GET /api/v1/profiles/kids/doh-setup.ps1":      []byte(script),
		"GET /api/v1/profiles/kids/apple.mobileconfig": []byte("<plist/>"),
	}

	path := filepath.Join(t.TempDir(), "doh-setup.ps1")
	out, f, err := runClient(t, newSetupCommand(), responses, "setup", "kids", "--device", "laptop", "--platform", "windows", "--download", path)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.requests[len(f.requests)-1]; got != "GET /api/v1/profiles/kids/doh-setup.ps1?device=laptop" {
		t.Errorf("requested %v", f.requests)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != script {
		t.Errorf("wrote %q, %v", b, err)
	}
	if !strings.Contains(out, "Wrote "+path) || !strings.Contains(out, "1. Download doh-setup.ps1 and read it.") {
		t.Errorf("output:\n%s", out)
	}

	// Versions of the configuration profile.
	for _, tt := range []struct {
		flags []string
		want  string
	}{
		{nil, "GET /api/v1/profiles/kids/apple.mobileconfig?device=laptop"},
		{[]string{"--protocol", "tls"}, "GET /api/v1/profiles/kids/apple.mobileconfig?device=laptop&protocol=tls"},
		{[]string{"--lock"}, "GET /api/v1/profiles/kids/apple.mobileconfig?device=laptop&lock=true"},
	} {
		args := append([]string{"setup", "kids", "--device", "laptop", "--platform", "mac", "--download", "-"}, tt.flags...)
		out, f, err := runClient(t, newSetupCommand(), responses, args...)
		if err != nil || out != "<plist/>" || f.requests[len(f.requests)-1] != tt.want {
			t.Errorf("%v = %q, %v, requests %v; want %s", tt.flags, out, err, f.requests, tt.want)
		}
	}

	// --mobileconfig --lock asks for the locked version.
	_, f, err = runClient(t, newSetupCommand(), responses, "setup", "kids", "--device", "ipad", "--lock", "--mobileconfig", "-")
	if err != nil || f.requests[0] != "GET /api/v1/profiles/kids/apple.mobileconfig?device=ipad&lock=true" {
		t.Errorf("--mobileconfig --lock: %v, requests %v", err, f.requests)
	}

	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"--platform", "smart-tv", "--download", "-"}, "no file to download"},
		{[]string{"--platform", "computers", "--download", "-"}, "is a group"},
		{[]string{"--platform", "windows", "--download", "-", "--protocol", "tls"}, "no such version"},
	} {
		_, _, err := runClient(t, newSetupCommand(), responses, append([]string{"setup", "kids"}, tt.args...)...)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%v: %v, want an error saying %q", tt.args, err, tt.want)
		}
	}
	for _, args := range [][]string{
		{"setup", "kids", "--download", "x"},                                             // whose?
		{"setup", "kids", "--platform", "mac", "--download", "x", "--mobileconfig", "y"}, // which?
		{"setup", "kids", "--lock"},                                                      // of what?
		{"setup", "kids", "--link", "--download", "x", "--platform", "mac"},
	} {
		if _, f, err := runClient(t, newSetupCommand(), responses, args...); err == nil || len(f.requests) != 0 {
			t.Errorf("%v: err %v, requests %v; want an error before any request", args, err, f.requests)
		}
	}
}
