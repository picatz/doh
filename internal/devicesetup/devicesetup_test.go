package devicesetup

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// golden compares got with testdata/name, or with -update, rewrites it.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from what was generated (run go test -update after checking the change):\n%s", name, got)
	}
}

var (
	v4  = netip.MustParseAddr("192.168.1.10")
	v6  = netip.MustParseAddr("fd00::10")
	pub = netip.MustParseAddr("203.0.113.7")
)

const template = "https://dns.example.com/dns-query/kids/laptop"

func TestWindowsScript(t *testing.T) {
	b, err := WindowsScript(Windows{Template: template, Addrs: []netip.Addr{pub, pub}, Profile: "kids", Device: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "doh-setup.ps1", b)
	s := string(b)

	for _, want := range []string{
		"$Template = '" + template + "'",
		"$HostName = 'dns.example.com'",
		"[string[]] $ServerAddress = @('203.0.113.7')", // once, though given twice
		"[CmdletBinding(SupportsShouldProcess = $true)]",
		"Add-DnsClientDohServerAddress -ServerAddress $address -DohTemplate $Template -AllowFallbackToUdp $false -AutoUpgrade $true",
		"Set-DnsClientServerAddress -InterfaceAlias $alias -ServerAddresses $ServerAddress",
		"Remove-DnsClientDohServerAddress",
		"-ResetServerAddresses",
		"[switch] $Revert",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	checkScriptSafety(t, s)

	// Every change asks ShouldProcess first, so -WhatIf changes nothing.
	changes := regexp.MustCompile(`(?m)^\s*(Add|Set|Remove|Clear)-DnsClient\w*`)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if !changes.MatchString(line) {
			continue
		}
		guarded := false
		for j := i - 1; j >= 0 && j >= i-4; j-- {
			if strings.Contains(lines[j], "$PSCmdlet.ShouldProcess(") {
				guarded = true
				break
			}
		}
		if !guarded {
			t.Errorf("line %d changes settings without ShouldProcess: %s", i+1, strings.TrimSpace(line))
		}
	}

	// Comments explain what it does: every non-blank line of code outside
	// the help block sits under a comment within a few lines.
	body := s[strings.Index(s, "#>")+2:]
	sinceComment := 0
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			sinceComment = 0
		case trimmed == "", trimmed == "}", strings.HasPrefix(trimmed, "} else"):
		default:
			sinceComment++
			if sinceComment > 12 {
				t.Errorf("a long stretch of code without a comment ends at %q", trimmed)
				sinceComment = 0
			}
		}
	}
}

func TestWindowsScript_LooksUpWithoutAddrs(t *testing.T) {
	b, err := WindowsScript(Windows{Template: "https://dns.example.com/dns-query/default", Profile: "default"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "[string[]] $ServerAddress = @()") || !strings.Contains(s, "Resolve-DnsName -Name $HostName") {
		t.Errorf("without addresses, the script should look the host name up:\n%s", s)
	}
	if strings.Contains(s, "as device") {
		t.Error("names a device though none was given")
	}
}

// checkScriptSafety checks that a script is ASCII and fetches nothing.
func checkScriptSafety(t *testing.T, s string) {
	t.Helper()
	for i, r := range s {
		if r > 0x7e || (r < 0x20 && r != '\n' && r != '\t') {
			t.Errorf("non-ASCII or control character %q at byte %d", r, i)
			break
		}
	}
	fetch := regexp.MustCompile(`(?i)invoke-webrequest|invoke-restmethod|invoke-expression|\biex\b|\biwr\b|\birm\b|downloadstring|downloadfile|net\.webclient|start-bitstransfer|\bcurl\b|\bwget\b|frombase64|-encodedcommand|http://`)
	if m := fetch.FindString(s); m != "" {
		t.Errorf("script fetches or runs remote code: %q", m)
	}
}

func TestWindowsScript_RefusesUnquotableValues(t *testing.T) {
	for _, w := range []Windows{
		{Template: "https://dns.example.com/dns-query/kids'; Remove-Item C:\\ -Recurse; '", Profile: "kids"},
		{Template: "https://dns.example.com/dns-query/$(calc)", Profile: "kids"},
		{Template: "https://dns.example.com/dns-query/kids\u2019", Profile: "kids"}, // PowerShell treats curly quotes as quotes
		{Template: "http://dns.example.com/dns-query", Profile: "kids"},
		{Template: "https://dns.example.com/dns-query?x=1", Profile: "kids"},
		{Template: "https://user@dns.example.com/dns-query", Profile: "kids"},
		{Template: "https://dns.example.com/dns-query", Profile: "kids'"},
		{Template: "https://dns.example.com/dns-query", Profile: "kids", Device: "a b"},
		{Template: "https://dns.example.com/dns-query", Profile: ""},
		{Template: "https://dns.example.com/dns-query", Profile: "kids", Addrs: []netip.Addr{{}}},
		{Template: "https://dns.example.com/dns-query", Profile: "kids", Addrs: make([]netip.Addr, MaxAddrs+1)},
		{Template: "https://dns.example.com/dns-query", Profile: "kids", Addrs: []netip.Addr{netip.IPv4Unspecified()}},
	} {
		if b, err := WindowsScript(w); err == nil {
			t.Errorf("WindowsScript(%+v) = nil error:\n%s", w, b)
		}
	}
}

func TestResolvedDropIn(t *testing.T) {
	b, err := ResolvedDropIn(Resolved{
		ServerName: "laptop--kids.dns.example.com",
		Addrs:      []netip.Addr{pub, netip.MustParseAddr("2001:db8::7%eth0")},
		Profile:    "kids", Device: "laptop",
	})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "doh.conf", b)
	s := string(b)
	checkScriptSafety(t, s)

	// The settings, exactly, in the [Resolve] section.
	_, section, ok := strings.Cut(s, "\n[Resolve]\n")
	if !ok {
		t.Fatalf("no [Resolve] section:\n%s", s)
	}
	var settings []string
	for _, line := range strings.Split(section, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			settings = append(settings, line)
		}
	}
	want := []string{
		"DNS=203.0.113.7#laptop--kids.dns.example.com 2001:db8::7#laptop--kids.dns.example.com",
		"DNSOverTLS=yes",
		"Domains=~.",
	}
	if strings.Join(settings, "\n") != strings.Join(want, "\n") {
		t.Errorf("settings =\n%s\nwant\n%s", strings.Join(settings, "\n"), strings.Join(want, "\n"))
	}
	if !strings.HasPrefix(s, "# "+ResolvedPath+"\n") {
		t.Errorf("doesn't start by naming its path")
	}

	for _, r := range []Resolved{
		{ServerName: "kids.dns.example.com", Profile: "kids"}, // no addresses
		{ServerName: "kids.dns.example.com\nDNSOverTLS=no", Addrs: []netip.Addr{pub}, Profile: "kids"},
		{ServerName: "kids.dns.example.com#x", Addrs: []netip.Addr{pub}, Profile: "kids"},
		{ServerName: "", Addrs: []netip.Addr{pub}, Profile: "kids"},
	} {
		if _, err := ResolvedDropIn(r); err == nil {
			t.Errorf("ResolvedDropIn(%+v) = nil error", r)
		}
	}
}

func TestOpenWrtScript(t *testing.T) {
	b, err := OpenWrtScript(OpenWrt{Addrs: []netip.Addr{v4, v6, netip.MustParseAddr("192.168.1.11")}, Profile: "default"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "doh-openwrt.sh", b)
	s := string(b)
	checkScriptSafety(t, s)

	apply, revert := section(t, s, "apply)"), section(t, s, "revert)")
	for _, want := range []string{
		"uci add_list dhcp.lan.dhcp_option='6,192.168.1.10,192.168.1.11'",
		"uci add_list dhcp.lan.dns='fd00::10'",
		"uci add_list dhcp.@dnsmasq[0].server='192.168.1.10'",
		"uci add_list dhcp.@dnsmasq[0].server='fd00::10'",
		"uci set dhcp.@dnsmasq[0].noresolv='1'",
	} {
		if !strings.Contains(apply, want) {
			t.Errorf("apply lacks %q", want)
		}
		// Whatever apply adds, revert takes away.
		if undo := strings.Replace(strings.Replace(want, "uci add_list", "uci -q del_list", 1), "uci set dhcp.@dnsmasq[0].noresolv='1'", "uci -q delete dhcp.@dnsmasq[0].noresolv", 1); !strings.Contains(revert, undo) {
			t.Errorf("revert lacks %q", undo)
		}
	}
	// Re-running apply doesn't add entries twice.
	if strings.Count(apply, "uci add_list") != strings.Count(apply, "uci -q del_list") {
		t.Error("apply adds list entries without removing them first")
	}
	if !strings.HasPrefix(s, "#!/bin/sh\n") || !strings.Contains(s, "set -eu\n") || !strings.HasSuffix(s, "uci commit dhcp\n/etc/init.d/dnsmasq restart\n") {
		t.Errorf("script frame:\n%s", s)
	}

	// IPv4 only: no odhcpd lines.
	b, err = OpenWrtScript(OpenWrt{Addrs: []netip.Addr{v4}, Profile: "default"})
	if err != nil || strings.Contains(string(b), "dhcp.lan.dns=") {
		t.Errorf("IPv4-only script = %v:\n%s", err, b)
	}

	if _, err := OpenWrtScript(OpenWrt{Profile: "default"}); err == nil {
		t.Error("made a script without addresses")
	}
}

// section returns the lines of a shell case branch.
func section(t *testing.T, s, label string) string {
	t.Helper()
	_, rest, ok := strings.Cut(s, "\n"+label+"\n")
	if !ok {
		t.Fatalf("no %s branch", label)
	}
	branch, _, _ := strings.Cut(rest, ";;")
	return branch
}

func TestOpenWrtScript_Shell(t *testing.T) {
	// The script is valid POSIX shell: dash parses it without running it.
	sh, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("needs dash")
	}
	b, err := OpenWrtScript(OpenWrt{Addrs: []netip.Addr{v4, v6}, Profile: "kids"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), OpenWrtFile)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), sh, "-n", path).CombinedOutput(); err != nil {
		t.Errorf("dash -n: %v\n%s", err, out)
	}
}
