// Package devicesetup writes the files that set a device or router up to
// use a doh server: a PowerShell script for Windows' built-in DNS over
// HTTPS, a systemd-resolved drop-in for DNS-over-TLS on Linux, and a shell
// script for OpenWrt routers.
//
// Each file is a pure function of its inputs, so the same profile, device,
// and server always give the same bytes. Every value that goes into a file
// is checked to be a plain host name, URL, address, or identifier, so none
// can change what a script does. The files fetch nothing over the network
// and are commented line by line, to read before running.
package devicesetup

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// MaxAddrs bounds the server addresses a file names.
const MaxAddrs = 8

// Windows describes a Windows setup script.
type Windows struct {
	// Template is the DNS-over-HTTPS URL that selects the profile and
	// device, such as https://dns.example.com/dns-query/kids/laptop.
	Template string

	// Addrs are the server's addresses, if known. Without them, the script
	// looks up the template's host name when it runs.
	Addrs []netip.Addr

	// Profile and Device are what the template selects, for the script's
	// comments.
	Profile, Device string
}

// Resolved describes a systemd-resolved drop-in.
type Resolved struct {
	// ServerName is the DNS-over-TLS host name that selects the profile and
	// device, such as tablet--kids.dns.example.com.
	ServerName string

	// Addrs are the server's addresses; systemd-resolved needs at least one.
	Addrs []netip.Addr

	// Profile and Device are what ServerName selects, for comments.
	Profile, Device string
}

// OpenWrt describes an OpenWrt setup script.
type OpenWrt struct {
	// Addrs are the plain DNS addresses of the doh server on the router's
	// network.
	Addrs []netip.Addr

	// Profile is the profile the script was made from, for comments: over
	// plain DNS, devices get profiles by address, whichever profile's
	// setup the script came from.
	Profile string
}

// WindowsFile, ResolvedFile, and OpenWrtFile are the files' names.
const (
	WindowsFile  = "doh-setup.ps1"
	ResolvedFile = "doh.conf"
	OpenWrtFile  = "doh-openwrt.sh"
)

// ResolvedPath is where the systemd-resolved drop-in goes.
const ResolvedPath = "/etc/systemd/resolved.conf.d/" + ResolvedFile

// WindowsScript returns a PowerShell script that registers w.Template as
// the DNS-over-HTTPS template for the server's addresses, with no fallback
// to plain DNS, and sets the connected network interfaces' DNS servers to
// them. It supports -WhatIf, to show what it would do, and -Revert, to
// undo it. It's ASCII, so Windows PowerShell 5.1 reads it the same in any
// code page.
func WindowsScript(w Windows) ([]byte, error) {
	u, err := checkTemplate(w.Template)
	if err != nil {
		return nil, err
	}
	addrs, err := checkAddrs(w.Addrs, false)
	if err != nil {
		return nil, err
	}
	if err := checkIDs(w.Profile, w.Device); err != nil {
		return nil, err
	}

	defaults := "@()"
	if len(addrs) > 0 {
		quoted := make([]string, len(addrs))
		for i, a := range addrs {
			quoted[i] = "'" + a.String() + "'"
		}
		defaults = "@(" + strings.Join(quoted, ", ") + ")"
	}
	return []byte(strings.NewReplacer(
		"{{template}}", w.Template,
		"{{hostname}}", u.Hostname(),
		"{{selects}}", selects(w.Profile, w.Device),
		"{{addrs}}", defaults,
	).Replace(windowsScript)), nil
}

// ResolvedDropIn returns a systemd-resolved drop-in, for ResolvedPath,
// that sends every lookup to the server over DNS-over-TLS, strictly, with
// r.ServerName as the TLS server name.
func ResolvedDropIn(r Resolved) ([]byte, error) {
	if !hostname(r.ServerName) {
		return nil, fmt.Errorf("devicesetup: %q isn't a host name", r.ServerName)
	}
	addrs, err := checkAddrs(r.Addrs, true)
	if err != nil {
		return nil, err
	}
	if err := checkIDs(r.Profile, r.Device); err != nil {
		return nil, err
	}

	servers := make([]string, len(addrs))
	for i, a := range addrs {
		// The port is the standard one, 853, which systemd-resolved uses
		// unless told otherwise.
		servers[i] = a.String() + "#" + r.ServerName
	}
	return []byte(strings.NewReplacer(
		"{{path}}", ResolvedPath,
		"{{file}}", ResolvedFile,
		"{{selects}}", selects(r.Profile, r.Device),
		"{{servers}}", strings.Join(servers, " "),
	).Replace(resolvedDropIn)), nil
}

// OpenWrtScript returns a shell script, run on an OpenWrt router, that
// hands out the server's addresses as the network's DNS servers over DHCP
// (and, for IPv6 addresses, router advertisements), and forwards the
// router's own resolver, dnsmasq, to the server. "sh doh-openwrt.sh
// revert" undoes it.
func OpenWrtScript(o OpenWrt) ([]byte, error) {
	addrs, err := checkAddrs(o.Addrs, true)
	if err != nil {
		return nil, err
	}
	if err := checkIDs(o.Profile, ""); err != nil {
		return nil, err
	}

	var v4, all []string
	var v6 []netip.Addr
	for _, a := range addrs {
		all = append(all, a.String())
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a)
		}
	}

	var apply, revert strings.Builder
	if len(v4) > 0 {
		option := "6," + strings.Join(v4, ",")
		apply.WriteString("\t# DHCP option 6 hands devices doh's IPv4 address as their DNS server, so\n" +
			"\t# they ask doh directly, and doh sees each device's own address. The\n" +
			"\t# del_list first keeps running this twice from adding it twice.\n")
		fmt.Fprintf(&apply, "\tuci -q del_list dhcp.lan.dhcp_option='%s' || true\n", option)
		fmt.Fprintf(&apply, "\tuci add_list dhcp.lan.dhcp_option='%s'\n", option)
		fmt.Fprintf(&revert, "\tuci -q del_list dhcp.lan.dhcp_option='%s' || true\n", option)
	}
	if len(v6) > 0 {
		apply.WriteString("\t# odhcpd announces doh's IPv6 addresses as DNS servers to IPv6 devices.\n")
		for _, a := range v6 {
			fmt.Fprintf(&apply, "\tuci -q del_list dhcp.lan.dns='%s' || true\n", a)
			fmt.Fprintf(&apply, "\tuci add_list dhcp.lan.dns='%s'\n", a)
			fmt.Fprintf(&revert, "\tuci -q del_list dhcp.lan.dns='%s' || true\n", a)
		}
	}
	apply.WriteString("\t# The router's own resolver, dnsmasq, forwards to doh too, so devices\n" +
		"\t# that still ask the router (such as over IPv6, or with a cached lease),\n" +
		"\t# and the router itself, go through doh. doh sees those as coming from\n" +
		"\t# the router's address.\n")
	for _, a := range all {
		fmt.Fprintf(&apply, "\tuci -q del_list dhcp.@dnsmasq[0].server='%s' || true\n", a)
		fmt.Fprintf(&apply, "\tuci add_list dhcp.@dnsmasq[0].server='%s'\n", a)
		fmt.Fprintf(&revert, "\tuci -q del_list dhcp.@dnsmasq[0].server='%s' || true\n", a)
	}
	apply.WriteString("\t# Use only doh, not also the DNS servers the internet provider hands the\n" +
		"\t# router, which would let lookups skip doh.\n" +
		"\tuci set dhcp.@dnsmasq[0].noresolv='1'\n")
	revert.WriteString("\t# Go back to the internet provider's DNS servers (OpenWrt's default).\n" +
		"\tuci -q delete dhcp.@dnsmasq[0].noresolv || true\n")

	return []byte(strings.NewReplacer(
		"{{file}}", OpenWrtFile,
		"{{profile}}", o.Profile,
		"{{addrs}}", strings.Join(all, ", "),
		"{{apply}}", apply.String(),
		"{{revert}}", revert.String(),
	).Replace(openWrtScript)), nil
}

// selects says what a file's settings select, for its comments.
func selects(profile, device string) string {
	s := "profile " + profile
	if device != "" {
		s += ", as device " + device
	}
	return s
}

// checkTemplate checks that t is an https URL of plain characters, as
// doh's DoH URLs are, so it can be quoted in a script as is.
func checkTemplate(t string) (*url.URL, error) {
	u, err := url.Parse(t)
	if err != nil || u.Scheme != "https" || !hostname(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(t) > 512 {
		return nil, fmt.Errorf("devicesetup: %q isn't a DNS-over-HTTPS URL", t)
	}
	for _, r := range t {
		if !plain(r) && !strings.ContainsRune(":/", r) {
			return nil, fmt.Errorf("devicesetup: %q has characters a script can't quote as is", t)
		}
	}
	return u, nil
}

// checkAddrs checks addrs, returning them without duplicates and zones.
func checkAddrs(addrs []netip.Addr, required bool) ([]netip.Addr, error) {
	if required && len(addrs) == 0 {
		return nil, errors.New("devicesetup: no server addresses")
	}
	if len(addrs) > MaxAddrs {
		return nil, fmt.Errorf("devicesetup: %d server addresses, more than %d", len(addrs), MaxAddrs)
	}
	var out []netip.Addr
	for _, a := range addrs {
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() {
			return nil, fmt.Errorf("devicesetup: %v isn't a server address", a)
		}
		a = a.Unmap().WithZone("")
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}

// checkIDs checks that profile and device, if set, are identifiers.
func checkIDs(profile, device string) error {
	for _, id := range []string{profile, device} {
		if len(id) > 63 || strings.IndexFunc(id, func(r rune) bool { return !plain(r) || r == '.' }) >= 0 {
			return fmt.Errorf("devicesetup: %q isn't a profile or device ID", id)
		}
	}
	if profile == "" {
		return errors.New("devicesetup: no profile")
	}
	return nil
}

// hostname reports whether s is a host name of letters, digits, hyphens,
// and dots.
func hostname(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return !plain(r) || r == '_' || r == '~' }) < 0
}

// plain reports whether r is an ASCII letter, digit, or one of -._~.
func plain(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("-._~", r)
}
