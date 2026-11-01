package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
