package cli

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/client"
	"github.com/spf13/cobra"
)

// Doctor check results.
const (
	doctorOK   = "ok"
	doctorWarn = "warn"
	doctorFail = "fail"
)

// Well-known resolver addresses doctor recognizes.
const (
	tailscaleResolver = "100.100.100.100"
	resolvedStub      = "127.0.0.53"
)

// firefoxCanary is the domain Firefox queries to decide whether a network
// allows it to enable its own DNS over HTTPS. Networks that filter answer
// it with NXDOMAIN.
const firefoxCanary = "use-application-dns.net."

// doctorCheck is the result of one diagnostic.
type doctorCheck struct {
	Status string `json:"status"`
	Title  string `json:"title"`
	Advice string `json:"advice,omitempty"`

	// Server is the resolver the check queried, if any.
	Server string `json:"server,omitempty"`

	// Identity holds the key=value fields a doh server reported for
	// itself, such as profile and device.
	Identity map[string]string `json:"identity,omitempty"`
}

// doctorEnv is what doctor inspects, injectable for tests.
type doctorEnv struct {
	// resolvConf is the path of the system's resolver configuration.
	resolvConf string

	// server, if set, is a doh DNS listener (host:port) to test directly.
	server string

	// goos is the operating system, as runtime.GOOS.
	goos string

	// exchange sends a DNS query to addr over UDP.
	exchange func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error)

	// adminAddr, if set, is checked for a reachable admin API.
	adminAddr string

	// health requests url, returning an error unless it answers 200 OK.
	health func(ctx context.Context, url string) error
}

// udpExchange returns an exchange function using UDP with timeout.
func udpExchange(timeout time.Duration) func(context.Context, *dns.Msg, string) (*dns.Msg, error) {
	return func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
		c := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, err := c.ExchangeContext(ctx, m, addr)
		return resp, err
	}
}

// httpHealth checks url with timeout.
func httpHealth(timeout time.Duration) func(context.Context, string) error {
	return func(ctx context.Context, url string) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s", resp.Status)
		}
		return nil
	}
}

// parseResolvConf returns the nameserver addresses in a resolv.conf file.
func parseResolvConf(r io.Reader) ([]string, error) {
	var servers []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	return servers, sc.Err()
}

// resolverAddr returns host:port for a nameserver address.
func resolverAddr(ns string) string {
	if _, _, err := net.SplitHostPort(ns); err == nil {
		return ns
	}
	return net.JoinHostPort(ns, "53")
}

// identify asks the resolver at addr who it is, with a CHAOS TXT query for
// id.server ([RFC 4892, Section 2.3]). doh answers with "doh" followed by
// key=value fields.
//
// [RFC 4892, Section 2.3]: https://www.rfc-editor.org/rfc/rfc4892.html#section-2.3
func identify(ctx context.Context, env doctorEnv, addr string) doctorCheck {
	m := new(dns.Msg)
	m.SetQuestion("id.server.", dns.TypeTXT)
	m.Question[0].Qclass = dns.ClassCHAOS

	check := doctorCheck{Server: addr}
	resp, err := env.exchange(ctx, m, addr)
	if err != nil {
		check.Status = doctorFail
		check.Title = fmt.Sprintf("%s didn't answer", addr)
		check.Advice = "check that the resolver is running and reachable: " + err.Error()
		return check
	}

	var txt string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			txt = strings.Join(t.Txt, " ")
			break
		}
	}

	fields := strings.Fields(txt)
	if len(fields) == 0 || fields[0] != "doh" {
		check.Status = doctorWarn
		check.Title = fmt.Sprintf("%s is not a doh server (answered: %s)", addr, cmp.Or(txt, dns.RcodeToString[resp.Rcode]))
		check.Advice = "queries sent here don't get doh's protections; point this device, or your router's DHCP DNS setting, at your doh server"
		return check
	}

	check.Identity = map[string]string{}
	for _, f := range fields[1:] {
		if k, v, ok := strings.Cut(f, "="); ok && k != "" {
			check.Identity[k] = v
		}
	}

	var parts []string
	for _, k := range []string{"profile", "device", "client"} {
		if v := check.Identity[k]; v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	check.Status = doctorOK
	check.Title = fmt.Sprintf("%s is answered by doh", addr)
	if len(parts) > 0 {
		check.Title += " (" + strings.Join(parts, ", ") + ")"
	}
	return check
}

// runDoctor runs every diagnostic in env.
func runDoctor(ctx context.Context, env doctorEnv) []doctorCheck {
	var checks []doctorCheck

	var servers []string
	f, err := os.Open(env.resolvConf)
	if err == nil {
		servers, err = parseResolvConf(f)
		f.Close()
	}
	switch {
	case err != nil:
		checks = append(checks, doctorCheck{Status: doctorWarn, Title: "can't read " + env.resolvConf, Advice: err.Error()})
	case len(servers) == 0:
		checks = append(checks, doctorCheck{Status: doctorWarn, Title: "no nameservers in " + env.resolvConf, Advice: "the system resolver falls back to localhost"})
	default:
		checks = append(checks, doctorCheck{Status: doctorOK, Title: "system nameservers: " + strings.Join(servers, ", ")})
	}

	if env.goos == "darwin" {
		checks = append(checks, doctorCheck{Status: doctorWarn, Title: "macOS doesn't always use /etc/resolv.conf",
			Advice: "run `scutil --dns` to see the resolvers macOS actually uses, including per-domain ones and VPNs"})
	}

	for _, ns := range servers {
		switch ns {
		case tailscaleResolver:
			checks = append(checks, doctorCheck{Status: doctorWarn, Server: ns, Title: "Tailscale MagicDNS is handling DNS",
				Advice: "queries go to Tailscale first; to keep this resolver's protections, add it as a global nameserver with \"Override local DNS\" in the Tailscale admin console, or run `tailscale set --accept-dns=false` on this device"})
		case resolvedStub:
			checks = append(checks, doctorCheck{Status: doctorWarn, Server: ns, Title: "systemd-resolved's stub resolver is handling DNS",
				Advice: "the stub forwards to other servers; run `resolvectl status` to see which, and check they're your doh server"})
		}
	}

	targets := servers
	if env.server != "" {
		targets = append([]string{env.server}, servers...)
	}
	seen := map[string]string{}
	for _, ns := range targets {
		addr := resolverAddr(ns)
		if _, ok := seen[addr]; ok {
			continue
		}
		c := identify(ctx, env, addr)
		seen[addr] = c.Status
		checks = append(checks, c)
	}

	// The canary only means something if the system resolver answers;
	// otherwise its result would be noise from a fallback.
	if len(servers) > 0 && seen[resolverAddr(servers[0])] != doctorFail {
		checks = append(checks, canary(ctx, env, resolverAddr(servers[0])))
	}

	if env.adminAddr != "" && env.health != nil {
		url := strings.TrimSuffix(env.adminAddr, "/") + "/healthz"
		if !strings.Contains(env.adminAddr, "://") {
			url = "http://" + url
		}
		if err := env.health(ctx, url); err == nil {
			checks = append(checks, doctorCheck{Status: doctorOK, Title: "admin API reachable at " + env.adminAddr})
		} else {
			checks = append(checks, doctorCheck{Status: doctorWarn, Title: "admin API not reachable at " + env.adminAddr,
				Advice: "start doh serve with --admin-listen, or set " + envAddr + " to its address, to manage it with doh status, doh log, and doh ui"})
		}
	}

	return checks
}

// canary checks how the resolver at addr answers Firefox's canary domain.
func canary(ctx context.Context, env doctorEnv, addr string) doctorCheck {
	m := new(dns.Msg)
	m.SetQuestion(firefoxCanary, dns.TypeA)

	resp, err := env.exchange(ctx, m, addr)
	switch {
	case err != nil:
		return doctorCheck{Status: doctorFail, Server: addr, Title: "couldn't check Firefox's canary domain", Advice: err.Error()}
	case resp.Rcode == dns.RcodeNameError:
		return doctorCheck{Status: doctorOK, Server: addr, Title: "Firefox will use this network's resolver"}
	default:
		return doctorCheck{Status: doctorWarn, Server: addr, Title: "Firefox may enable its own DNS over HTTPS and bypass filtering",
			Advice: firefoxCanary + " resolves here; doh answers it with NXDOMAIN for profiles that block anything"}
	}
}

// doctorMarks are the symbols printed for each result.
var doctorMarks = map[string]string{doctorOK: "✓", doctorWarn: "!", doctorFail: "✗"}

// printDoctor writes checks for people.
func printDoctor(w io.Writer, checks []doctorCheck) error {
	for _, c := range checks {
		if _, err := fmt.Fprintf(w, "%s %s\n", doctorMarks[c.Status], c.Title); err != nil {
			return err
		}
		if c.Advice != "" {
			if _, err := fmt.Fprintf(w, "  %s\n", c.Advice); err != nil {
				return err
			}
		}
	}
	return nil
}

// newDoctorCommand returns "doh doctor".
func newDoctorCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that this device's DNS goes through doh",
		Long: `Check that this device's DNS queries reach a doh server, and that nothing
routes around it.

doctor reads the system's nameservers, recognizes Tailscale MagicDNS and the
systemd-resolved stub, asks each nameserver who it is (a CHAOS TXT query for
id.server, which doh answers with its profile and device), checks Firefox's
DNS over HTTPS canary domain, and looks for the admin API at --addr. It needs
no API token.

Examples:
  doh doctor

  # Also test a doh DNS listener directly
  doh doctor --server 192.168.1.10:53`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	fs := cmd.Flags()
	resolvConf := fs.String("resolv-conf", "/etc/resolv.conf", "resolver configuration to read")
	_ = fs.MarkHidden("resolv-conf")
	server := fs.String("server", "", "a doh DNS listener to test directly, such as 192.168.1.10:53")
	asJSON := fs.Bool("json", false, "print JSON instead of text")
	timeout := fs.Duration("timeout", 3*time.Second, "timeout for each query")
	addr := fs.String("addr", cmp.Or(os.Getenv(envAddr), client.DefaultAddr), "admin API address to check ("+envAddr+")")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		checks := runDoctor(cmd.Context(), doctorEnv{
			resolvConf: *resolvConf,
			server:     *server,
			goos:       runtime.GOOS,
			exchange:   udpExchange(*timeout),
			adminAddr:  *addr,
			health:     httpHealth(time.Second),
		})
		if *asJSON {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(checks)
		}
		return printDoctor(cmd.OutOrStdout(), checks)
	}
	return cmd
}

func init() {
	CommandRoot.AddCommand(newDoctorCommand())
}
