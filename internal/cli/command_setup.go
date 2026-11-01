package cli

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/picatz/doh/internal/api"
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
instructions for iPhone, iPad, and Mac, Android, Windows, Linux, browsers, and
your whole network.

Naming the device with --device makes the server's query log show its name.
For Apple devices, --mobileconfig writes a configuration profile to open on
the device, which sets up encrypted DNS in one step.

Encrypted settings need the server's public host name (doh serve --hostname,
or an ACME domain); DNS-over-TLS, which Android uses, needs --dot-listen too.

Examples:
  doh setup default
  doh setup kids --device tablet --platform android
  doh setup kids --device ipad --mobileconfig ipad.mobileconfig
  doh setup kids --device mac --protocol tls --mobileconfig - > mac.mobileconfig`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}

	f := addClientFlags(cmd)
	fs := cmd.Flags()
	device := fs.String("device", "", "name the device, as lower-case letters, digits, and hyphens, so logs show it")
	platform := fs.String("platform", "", "show only this platform: apple, android, windows, linux, browser, or router")
	mobileconfig := fs.String("mobileconfig", "", `write an Apple configuration profile to this file ("-" for standard output)`)
	protocol := fs.String("protocol", "", "protocol for --mobileconfig: https or tls (default https if the server serves it)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		profile := args[0]
		switch *protocol {
		case "", "https", "tls":
		default:
			return fmt.Errorf("--protocol must be https or tls, not %q", *protocol)
		}
		if *protocol != "" && *mobileconfig == "" {
			return fmt.Errorf("--protocol only applies with --mobileconfig")
		}

		c, err := f.client()
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()

		if *mobileconfig != "" {
			b, err := c.MobileConfig(cmd.Context(), profile, *device, *protocol)
			if err != nil {
				return err
			}
			if *mobileconfig == "-" {
				_, err := out.Write(b)
				return err
			}
			if err := os.WriteFile(*mobileconfig, b, 0o644); err != nil {
				return err
			}
			if f.json {
				return printJSON(out, map[string]string{"mobileconfig": *mobileconfig})
			}
			fmt.Fprintf(out, "Wrote %s.\n\n", *mobileconfig)
			fmt.Fprintln(out, wrap("Send it to the device, by AirDrop, email, or a file share, and open it there. "+
				"On iPhone and iPad, then open Settings and tap Profile Downloaded to install it; "+
				"on a Mac, open System Settings, then Privacy & Security, then Profiles.", setupWidth, ""))
			return nil
		}

		setup, err := c.Setup(cmd.Context(), profile, *device)
		if err != nil {
			return err
		}

		if *platform != "" {
			i := slices.IndexFunc(setup.Platforms, func(p api.Platform) bool { return p.ID == *platform })
			if i < 0 {
				ids := make([]string, len(setup.Platforms))
				for i, p := range setup.Platforms {
					ids[i] = p.ID
				}
				return fmt.Errorf("profile %s has no instructions for %q; this server can set up: %s", profile, *platform, strings.Join(ids, ", "))
			}
			setup.Platforms = setup.Platforms[i : i+1]
		}

		if f.json {
			return printJSON(out, setup)
		}
		return printSetup(out, setup)
	}
	return cmd
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

	for _, p := range setup.Platforms {
		fmt.Fprintf(w, "\n%s\n", p.Name)
		for i, step := range p.Steps {
			marker := fmt.Sprintf("  %d. ", i+1)
			fmt.Fprintln(w, marker+wrap(step, setupWidth-len(marker), strings.Repeat(" ", len(marker))))
		}
		if p.ID == "apple" && p.Download != "" {
			cmd := "doh setup " + setup.Profile
			if setup.Device != "" {
				cmd += " --device " + setup.Device
			}
			name := setup.Profile
			if setup.Device != "" {
				name += "-" + setup.Device
			}
			fmt.Fprintf(w, "  Get the configuration profile with:\n    %s --mobileconfig %s.mobileconfig\n", cmd, name)
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
