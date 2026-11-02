package cli

import (
	"cmp"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/qr"
	"github.com/spf13/cobra"
)

// setupWidth is the width setup instructions are wrapped to.
const setupWidth = 80

// newSetupCommand returns "doh setup".
func newSetupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup <profile>",
		Short: "Show how to connect a device to a profile",
		Long: `Show how to connect a device to a profile of a running doh server: the
DNS-over-HTTPS URL and DNS-over-TLS host name that select it, and step-by-step
instructions for every kind of device, grouped: phones and tablets (iPhone,
iPad, Apple Vision Pro, Android), computers (Mac, Windows, Linux, Chromebook),
TV and streaming (Apple TV, Android TV, smart TVs), game consoles, smart home
devices, browsers, and your whole network (any router, OpenWrt, pfSense and
OPNsense, UniFi). Each says how well it's protected (encrypted, or plain DNS),
how to check it's working, and how doh tells which device is asking.

--list lists the platforms in a table, and --platform shows only one platform,
or one group (phones, computers, tv, consoles, smart-home, browsers, network).

Naming the device with --device makes the server's query log show its name.
Some platforms have files that set them up: --download writes the platform's
file, such as an Apple configuration profile, a PowerShell script for
Windows (doh-setup.ps1), a systemd-resolved drop-in for Linux (doh.conf), or
a script for OpenWrt routers (doh-openwrt.sh). Read scripts before running
them. --mobileconfig writes an Apple configuration profile directly.

With --link, it makes a setup link instead: a page to open on the device
itself, with one-tap install on Apple devices, shown as a QR code to scan
with its camera. It works for 30 minutes.

Encrypted settings need the server's public host name (doh serve --hostname,
or an ACME domain); DNS-over-TLS, which Android uses, needs --dot-listen too.
Devices that only speak plain DNS need --dns-listen on your network.

Examples:
  doh setup default
  doh setup default --list
  doh setup kids --device tablet --platform android
  doh setup kids --platform tv
  doh setup kids --device laptop --platform windows --download doh-setup.ps1
  doh setup kids --device laptop --platform linux --download doh.conf
  doh setup default --platform openwrt --download doh-openwrt.sh
  doh setup kids --device ipad --mobileconfig ipad.mobileconfig
  doh setup kids --device mac --protocol tls --mobileconfig - > mac.mobileconfig
  doh setup kids --device ipad --platform apple --lock --download ipad.mobileconfig
  doh setup kids --device ipad --link`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}

	f := addClientFlags(cmd)
	fs := cmd.Flags()
	device := fs.String("device", "", "name the device, as lower-case letters, digits, and hyphens, so logs show it")
	platform := fs.String("platform", "", "show only this platform (such as apple, android, windows, linux, smart-tv, or openwrt), or group (such as tv or network)")
	list := fs.Bool("list", false, "list the platforms, with their group and protection")
	download := fs.String("download", "", `write the --platform's setup file to this file ("-" for standard output)`)
	mobileconfig := fs.String("mobileconfig", "", `write an Apple configuration profile to this file ("-" for standard output)`)
	protocol := fs.String("protocol", "", "protocol of an Apple configuration profile: https or tls (default https if the server serves it)")
	lock := fs.Bool("lock", false, "make an Apple configuration profile whose DNS setting can't be turned off, on supervised devices")
	link := fs.Bool("link", false, "make a setup link to open on the device, shown as a QR code")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		profile := args[0]
		switch *protocol {
		case "", "https", "tls":
		default:
			return fmt.Errorf("--protocol must be https or tls, not %q", *protocol)
		}
		if (*protocol != "" || *lock) && *mobileconfig == "" && *download == "" {
			return fmt.Errorf("--protocol and --lock only apply with --mobileconfig or --download")
		}
		if *link && (*mobileconfig != "" || *platform != "" || *download != "" || *list) {
			return fmt.Errorf("--link makes a link for any platform, so it can't be used with --mobileconfig, --download, --list, or --platform")
		}
		if *download != "" && (*platform == "" || *mobileconfig != "") {
			return fmt.Errorf("--download needs --platform, to say whose file, and can't be used with --mobileconfig")
		}

		c, err := f.client()
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()

		if *link {
			l, err := c.CreateSetupLink(cmd.Context(), profile, *device)
			if err != nil {
				return err
			}
			if f.json {
				return printJSON(out, l)
			}
			return printSetupLink(out, l)
		}

		if *mobileconfig != "" {
			var b []byte
			var err error
			if *lock {
				b, err = c.Download(cmd.Context(), api.Download{Path: lockedMobileConfigPath(profile, *device, *protocol), ContentType: api.MobileConfigType})
			} else {
				b, err = c.MobileConfig(cmd.Context(), profile, *device, *protocol)
			}
			if err != nil {
				return err
			}
			return writeSetupFile(out, *mobileconfig, b, f.json, "mobileconfig",
				"Send it to the device, by AirDrop, email, or a file share, and open it there. "+
					"On iPhone and iPad, then open Settings and tap Profile Downloaded to install it; "+
					"on a Mac, open System Settings and install it where downloaded profiles are listed.")
		}

		setup, err := c.Setup(cmd.Context(), profile, *device)
		if err != nil {
			return err
		}

		if *platform != "" {
			var matched []api.Platform
			for _, p := range setup.Platforms {
				if p.ID == *platform || p.Group == *platform {
					matched = append(matched, p)
				}
			}
			if len(matched) == 0 {
				var ids []string
				for _, p := range setup.Platforms {
					ids = append(ids, p.ID)
				}
				for _, g := range setup.Groups {
					ids = append(ids, g.ID)
				}
				return fmt.Errorf("profile %s has no instructions for %q; this server can set up: %s", profile, *platform, strings.Join(slices.Compact(ids), ", "))
			}
			setup.Platforms = matched
		}

		if *download != "" {
			if len(setup.Platforms) != 1 {
				return fmt.Errorf("--download needs one platform, and %q is a group: name a platform in it", *platform)
			}
			p := setup.Platforms[0]
			d, err := chooseDownload(p, *protocol, *lock)
			if err != nil {
				return err
			}
			b, err := c.Download(cmd.Context(), d)
			if err != nil {
				return err
			}
			return writeSetupFile(out, *download, b, f.json, "download", "Read it before using it; "+p.Name+"'s steps say what to do with it:\n"+formatSteps(p.Steps))
		}

		if *list {
			if f.json {
				return printJSON(out, setup.Platforms)
			}
			return printPlatformList(out, setup)
		}
		if f.json {
			return printJSON(out, setup)
		}
		return printSetup(out, setup)
	}
	return cmd
}

// lockedMobileConfigPath is the API path of a locked Apple configuration
// profile.
func lockedMobileConfigPath(profile, device, protocol string) string {
	q := url.Values{"lock": {"true"}}
	if device != "" {
		q.Set("device", device)
	}
	if protocol != "" {
		q.Set("protocol", protocol)
	}
	return api.Prefix + "/profiles/" + url.PathEscape(profile) + "/apple.mobileconfig?" + q.Encode()
}

// chooseDownload picks p's download that matches protocol and lock: the
// first, unless they ask for another version.
func chooseDownload(p api.Platform, protocol string, lock bool) (api.Download, error) {
	if len(p.Downloads) == 0 {
		return api.Download{}, fmt.Errorf("%s has no file to download; follow its steps instead", p.Name)
	}
	for _, d := range p.Downloads {
		u, err := url.Parse(d.Path)
		if err != nil {
			continue
		}
		q := u.Query()
		if (q.Get("lock") == "true") != lock {
			continue
		}
		if protocol != "" && q.Get("protocol") != protocol && (protocol != "https" || q.Has("protocol")) {
			continue
		}
		return d, nil
	}
	var names []string
	for _, d := range p.Downloads {
		names = append(names, d.Name)
	}
	return api.Download{}, fmt.Errorf("%s has no such version to download; it has: %s", p.Name, strings.Join(names, "; "))
}

// writeSetupFile writes b to path, or "-" for out, then says what to do
// with it.
func writeSetupFile(out io.Writer, path string, b []byte, asJSON bool, key, next string) error {
	if path == "-" {
		_, err := out.Write(b)
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	if asJSON {
		return printJSON(out, map[string]string{key: path})
	}
	fmt.Fprintf(out, "Wrote %s.\n\n", path)
	first, rest, _ := strings.Cut(next, "\n")
	fmt.Fprintln(out, wrap(first, setupWidth, ""))
	if rest != "" {
		fmt.Fprint(out, rest)
	}
	return nil
}

// printSetupLink writes a setup link, and the QR code to scan for it.
func printSetupLink(w io.Writer, l *api.SetupLink) error {
	fmt.Fprintf(w, "Open this on the device, or scan it with its camera. It works until %s.\n\n", l.Expires.Local().Format(time.Kitchen))
	if code, err := qr.Encode([]byte(l.URL), qr.M); err == nil {
		if err := code.WriteText(w, 2); err != nil {
			return err
		}
		fmt.Fprintln(w)
	}
	_, err := fmt.Fprintf(w, "  %s\n", l.URL)
	return err
}

// printPlatformList writes setup's platforms as a table.
func printPlatformList(w io.Writer, setup *api.Setup) error {
	groups := map[string]string{}
	for _, g := range setup.Groups {
		groups[g.ID] = g.Name
	}
	tw := newTable(w)
	fmt.Fprintln(tw, "PLATFORM\tGROUP\tPROTECTION\tNAME")
	for _, p := range setup.Platforms {
		level := "-"
		if p.Protection != nil {
			level = protectionLabel(p.Protection)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.ID, cmp.Or(groups[p.Group], "-"), level, p.Name)
	}
	return tw.Flush()
}

// protectionLabel describes a protection level in a few words.
func protectionLabel(p *api.Protection) string {
	switch {
	case p.Level == api.ProtectionEncrypted && p.Protocol == "https":
		return "encrypted, DoH"
	case p.Level == api.ProtectionEncrypted && p.Protocol == "tls":
		return "encrypted, DoT"
	case p.Level == api.ProtectionPlain:
		return "plain DNS"
	case p.Level == api.ProtectionUnavailable:
		return "not available"
	}
	return p.Level
}

// formatSteps numbers and wraps steps, indented.
func formatSteps(steps []string) string {
	var b strings.Builder
	for i, step := range steps {
		marker := fmt.Sprintf("  %d. ", i+1)
		b.WriteString(marker + wrap(step, setupWidth-len(marker), strings.Repeat(" ", len(marker))) + "\n")
	}
	return b.String()
}

// printSetup writes setup's settings and instructions for people.
func printSetup(w io.Writer, setup *api.Setup) error {
	title := "Connect a device to profile " + setup.Profile
	if setup.Device != "" {
		title += " as " + setup.Device
	}
	fmt.Fprintln(w, title)

	tw := newTable(w)
	if setup.DoHURL != "" {
		fmt.Fprintf(tw, "  DNS-over-HTTPS\t%s\n", setup.DoHURL)
	}
	if setup.DoTHost != "" {
		fmt.Fprintf(tw, "  DNS-over-TLS\t%s\n", setup.DoTHost)
	}
	if len(setup.DNSAddrs) > 0 {
		fmt.Fprintf(tw, "  Plain DNS\t%s\n", strings.Join(setup.DNSAddrs, ", "))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	groups := map[string]string{}
	for _, g := range setup.Groups {
		groups[g.ID] = g.Name
	}
	cmd := "doh setup " + setup.Profile
	if setup.Device != "" {
		cmd += " --device " + setup.Device
	}

	group := ""
	for _, p := range setup.Platforms {
		if name := groups[p.Group]; name != "" && p.Group != group {
			group = p.Group
			fmt.Fprintf(w, "\n%s\n%s\n", strings.ToUpper(name), strings.Repeat("=", len(name)))
		}
		heading := p.Name
		if p.Protection != nil {
			heading += " (" + protectionLabel(p.Protection) + ")"
		}
		fmt.Fprintf(w, "\n%s\n", heading)
		if p.Protection != nil && p.Protection.Summary != "" {
			fmt.Fprintln(w, "  "+wrap(p.Protection.Summary, setupWidth-2, "  "))
		}
		fmt.Fprint(w, formatSteps(p.Steps))

		switch {
		case len(p.Downloads) > 0:
			d := p.Downloads[0]
			fmt.Fprintf(w, "  Download it (%s) with:\n    %s --platform %s --download %s\n", d.Name, cmd, p.ID, d.File)
			if len(p.Downloads) > 1 {
				fmt.Fprintln(w, "    (other versions: --protocol tls, --lock)")
			}
		case p.ID == "apple" && p.Download != "":
			name := setup.Profile
			if setup.Device != "" {
				name += "-" + setup.Device
			}
			fmt.Fprintf(w, "  Get the configuration profile with:\n    %s --mobileconfig %s.mobileconfig\n", cmd, name)
		}
		for _, line := range []struct{ label, text string }{{"Check", p.Check}, {"How doh knows it", p.Identified}} {
			if line.text != "" {
				label := "  " + line.label + ": "
				fmt.Fprintln(w, label+wrap(line.text, setupWidth-len(label), "    "))
			}
		}
		for _, note := range p.Notes {
			fmt.Fprintln(w, "  - "+wrap(note, setupWidth-4, "    "))
		}
	}
	return nil
}

// wrap breaks s into lines of at most width bytes, between words, starting
// each line after the first with indent. Words longer than width, such as
// URLs, stay whole.
func wrap(s string, width int, indent string) string {
	var b strings.Builder
	line := 0
	for i, word := range strings.Fields(s) {
		switch {
		case i == 0:
		case line+1+len(word) > width:
			b.WriteString("\n" + indent)
			line = 0
		default:
			b.WriteByte(' ')
			line++
		}
		b.WriteString(word)
		line += len(word)
	}
	return b.String()
}
