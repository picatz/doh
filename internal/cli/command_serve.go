package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/serve"
	"github.com/picatz/doh/pkg/doh"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// envPrefix prefixes the environment variable for each serve flag, such
// that --tls-cert can also be set with DOH_TLS_CERT.
const envPrefix = "DOH_"

// serveOption is a serve flag and the config field it sets.
type serveOption struct {
	name string

	// define adds the flag to a flag set, returning a function that copies
	// the flag's current value into a config.
	define func(fs *pflag.FlagSet) (apply func(*serve.Config))
}

// option returns a serve option for a flag defined with define, such as
// (*pflag.FlagSet).String, whose value is copied into a config with set.
func option[T any](
	define func(fs *pflag.FlagSet, name string, value T, usage string) *T,
	name string, value T, usage string,
	set func(c *serve.Config, v T),
) serveOption {
	return serveOption{
		name: name,
		define: func(fs *pflag.FlagSet) func(*serve.Config) {
			p := define(fs, name, value, usage)
			return func(c *serve.Config) { set(c, *p) }
		},
	}
}

// serveOptions are the serve flags, in the order they're applied.
var serveOptions = []serveOption{
	option((*pflag.FlagSet).String, "listen", "", `address to listen on (default ":443", or ":8080" with --plaintext)`,
		func(c *serve.Config, v string) { c.Listen = v }),
	option((*pflag.FlagSet).String, "dns-listen", "", "also serve plain DNS over UDP and TCP on this address, such as :53",
		func(c *serve.Config, v string) { c.DNSListen = v }),
	option((*pflag.FlagSet).String, "dot-listen", "", "also serve DNS-over-TLS on this address, such as :853, with the DoH certificate",
		func(c *serve.Config, v string) { c.DoTListen = v }),
	option((*pflag.FlagSet).String, "doq-listen", "", "also serve DNS-over-QUIC (experimental) on this UDP address, such as :853, with the DoH certificate",
		func(c *serve.Config, v string) { c.DoQListen = v }),
	option((*pflag.FlagSet).String, "hostname", "", "public host name, such as dns.example.com, under which profiles are reachable as {profile}.{hostname} (default the first --acme-domain)",
		func(c *serve.Config, v string) { c.Hostname = v }),
	option((*pflag.FlagSet).String, "path", doh.DefaultPath, "URI path of the DoH endpoint",
		func(c *serve.Config, v string) { c.Path = v }),
	option((*pflag.FlagSet).StringSlice, "upstream", serve.DefaultUpstreams, "upstream resolvers, in order of preference",
		func(c *serve.Config, v []string) { c.Upstreams = v }),
	option((*pflag.FlagSet).Duration, "timeout", serve.DefaultTimeout, "maximum time to answer each query",
		func(c *serve.Config, v time.Duration) { c.Timeout = serve.Duration(v) }),
	option((*pflag.FlagSet).String, "tls-cert", "", "TLS certificate chain file (PEM)",
		func(c *serve.Config, v string) { c.TLS.CertFile = v }),
	option((*pflag.FlagSet).String, "tls-key", "", "TLS private key file (PEM)",
		func(c *serve.Config, v string) { c.TLS.KeyFile = v }),
	option((*pflag.FlagSet).String, "profile-signing-cert", "", "certificate chain file (PEM) to sign Apple configuration profiles with (default the TLS certificate)",
		func(c *serve.Config, v string) { c.TLS.ProfileSigning.CertFile = v }),
	option((*pflag.FlagSet).String, "profile-signing-key", "", "private key file (PEM, ECDSA or RSA) for --profile-signing-cert",
		func(c *serve.Config, v string) { c.TLS.ProfileSigning.KeyFile = v }),
	option((*pflag.FlagSet).String, "tls-min-version", "1.2", "oldest TLS version to accept: 1.2 or 1.3 (TLS 1.3 is preferred either way)",
		func(c *serve.Config, v string) { c.TLS.MinVersion = v }),
	option((*pflag.FlagSet).StringSlice, "acme-domain", nil, "domains to obtain ACME certificates for, enabling ACME",
		func(c *serve.Config, v []string) { c.TLS.ACME.Domains = v }),
	option((*pflag.FlagSet).String, "acme-email", "", "contact email for the ACME account",
		func(c *serve.Config, v string) { c.TLS.ACME.Email = v }),
	option((*pflag.FlagSet).String, "acme-cache-dir", "", "directory for ACME accounts and certificates (default user cache dir)",
		func(c *serve.Config, v string) { c.TLS.ACME.CacheDir = v }),
	option((*pflag.FlagSet).String, "acme-directory", "", "ACME directory URL (default Let's Encrypt)",
		func(c *serve.Config, v string) { c.TLS.ACME.DirectoryURL = v }),
	option((*pflag.FlagSet).String, "acme-http-listen", "", "address to answer ACME HTTP-01 challenges on, such as :80",
		func(c *serve.Config, v string) { c.TLS.ACME.HTTPListen = v }),
	option((*pflag.FlagSet).Bool, "plaintext", false, "serve unencrypted HTTP, behind a TLS-terminating proxy",
		func(c *serve.Config, v bool) { c.Plaintext = v }),
	option((*pflag.FlagSet).StringSlice, "blocklist", nil, "block names on these lists: presets (default, "+strings.Join(blocklist.PresetNames(), ", ")+"), URLs, or files, as [name=]location",
		func(c *serve.Config, v []string) { c.Blocklist.Sources = v }),
	option((*pflag.FlagSet).StringSlice, "block-domain", nil, "also block these domains and their subdomains",
		func(c *serve.Config, v []string) { c.Blocklist.Block = v }),
	option((*pflag.FlagSet).StringSlice, "allow-domain", nil, "never block these domains and their subdomains",
		func(c *serve.Config, v []string) { c.Blocklist.Allow = v }),
	option((*pflag.FlagSet).String, "block-response", serve.BlockNXDomain, "answer blocked names with nxdomain, or null (0.0.0.0 and ::)",
		func(c *serve.Config, v string) { c.Blocklist.Response = v }),
	option((*pflag.FlagSet).Duration, "blocklist-refresh", serve.DefaultBlocklistRefresh, "how often to reload blocklists",
		func(c *serve.Config, v time.Duration) { c.Blocklist.Refresh = serve.Duration(v) }),
	option((*pflag.FlagSet).Int, "cache-size", serve.DefaultCacheSize, "most upstream answers to cache, for as long as their records live; 0 disables the cache",
		func(c *serve.Config, v int) { c.Cache.Size, c.Cache.Disabled = v, v == 0 }),
	option((*pflag.FlagSet).String, "data-dir", "", "directory for the policy, admin API tokens, query log, and registration cache (default $STATE_DIRECTORY, or doh in the user config dir)",
		func(c *serve.Config, v string) { c.DataDir = v }),
	option((*pflag.FlagSet).String, "policy", "", `policy file (default policy.json in --data-dir), URL of another doh server's /api/v1/policy to follow read-only, or "off"`,
		func(c *serve.Config, v string) { c.Policy.Source = v }),
	option((*pflag.FlagSet).String, "policy-token-file", "", "file holding the bearer token for a --policy URL",
		func(c *serve.Config, v string) { c.Policy.TokenFile = v }),
	option((*pflag.FlagSet).StringSlice, "forward", nil, "send names under a domain to other upstreams, as domain=upstream, such as lan=192.168.1.1",
		func(c *serve.Config, v []string) {
			c.Forward = make(map[string][]string, len(v))
			for _, f := range v {
				domain, up, _ := strings.Cut(f, "=")
				c.Forward[domain] = append(c.Forward[domain], up)
			}
		}),
	option((*pflag.FlagSet).StringSlice, "device-names-from", nil, "DNS servers to ask for device names by reverse lookup, such as your router at 192.168.1.1 (default the forward zones, then the default gateway)",
		func(c *serve.Config, v []string) { c.DeviceNames.Resolvers = v }),
	option((*pflag.FlagSet).StringSlice, "dhcp-leases", nil, "DHCP lease files to read device names from: dnsmasq's, or Kea's CSV",
		func(c *serve.Config, v []string) { c.DeviceNames.Leases = v }),
	option((*pflag.FlagSet).Bool, "no-device-names", false, "don't learn device names from the network",
		func(c *serve.Config, v bool) { c.DeviceNames.Disabled = v }),
	option((*pflag.FlagSet).StringSlice, "trusted-proxy", nil, "addresses or prefixes of reverse proxies whose X-Forwarded-For names DoH clients",
		func(c *serve.Config, v []string) { c.TrustedProxies = v }),
	option((*pflag.FlagSet).Bool, "no-query-log", false, "don't log queries",
		func(c *serve.Config, v bool) { c.QueryLog.Disabled = v }),
	option((*pflag.FlagSet).Duration, "query-log-retention", 0, "how long to keep daily query log files (default 168h)",
		func(c *serve.Config, v time.Duration) { c.QueryLog.Retention = serve.Duration(v) }),
	option((*pflag.FlagSet).StringSlice, "admin-origin", nil, "origins the web UI is opened at, such as https://admin.dns.example.com, for browser sign-in and passkeys (default http://localhost:{port} on a loopback --admin-listen)",
		func(c *serve.Config, v []string) { c.Admin.Origins = v }),
	option((*pflag.FlagSet).String, "smtp-url", "", "mail server for email alerts: smtp://user@host:587 (STARTTLS required) or smtps://user@host:465; the password goes in --smtp-password-file or $"+serve.SMTPPasswordEnv+", never here",
		func(c *serve.Config, v string) { c.Alerts.SMTP.URL = v }),
	option((*pflag.FlagSet).String, "smtp-password-file", "", "file holding the --smtp-url user's password",
		func(c *serve.Config, v string) { c.Alerts.SMTP.PasswordFile = v }),
	option((*pflag.FlagSet).String, "smtp-from", "", `sender of email alerts, such as "doh <alerts@example.com>"`,
		func(c *serve.Config, v string) { c.Alerts.SMTP.From = v }),
	option((*pflag.FlagSet).String, "admin-token-file", "", "file holding the admin API token (default admin.token in --data-dir, generated)",
		func(c *serve.Config, v string) { c.Admin.TokenFile = v }),
	option((*pflag.FlagSet).String, "admin-listen", "", "serve metrics, pprof, and flight recorder snapshots on this address, such as localhost:9090",
		func(c *serve.Config, v string) { c.Admin.Listen = v }),
	option((*pflag.FlagSet).Bool, "flight-recorder", false, "keep recent execution traces in memory, to snapshot from the admin listener",
		func(c *serve.Config, v bool) { c.Admin.FlightRecorder = v }),
	option((*pflag.FlagSet).Duration, "slow-query", 0, "save a flight recorder snapshot to --trace-dir when a query takes this long",
		func(c *serve.Config, v time.Duration) { c.Admin.SlowQuery = serve.Duration(v) }),
	option((*pflag.FlagSet).String, "trace-dir", "", "directory for slow query flight recorder snapshots",
		func(c *serve.Config, v string) { c.Admin.TraceDir = v }),
	option((*pflag.FlagSet).String, "log-level", "info", "log level: debug, info, warn, or error",
		func(c *serve.Config, v string) { c.Log.Level = v }),
	option((*pflag.FlagSet).String, "log-format", "text", "log format: text or json",
		func(c *serve.Config, v string) { c.Log.Format = v }),
}

// serveFlags holds the serve flags defined on a flag set, and how to apply
// each to a config.
type serveFlags struct {
	fs    *pflag.FlagSet
	apply map[string]func(*serve.Config)
}

// defineServeFlags defines the config flag and every serve option on fs.
func defineServeFlags(fs *pflag.FlagSet) serveFlags {
	fs.String("config", "", "path to a JSON config file")

	flags := serveFlags{fs: fs, apply: make(map[string]func(*serve.Config), len(serveOptions))}
	for _, o := range serveOptions {
		flags.apply[o.name] = o.define(fs)
	}

	return flags
}

// newServeCommand returns the "doh serve" command.
func newServeCommand() *cobra.Command {
	var flags serveFlags

	cmd := &cobra.Command{
		Use:   "serve [flags]",
		Short: "Serve DNS-over-HTTPS, forwarding queries to upstream resolvers",
		Long: `Serve DNS-over-HTTPS (RFC 8484), forwarding queries to upstream resolvers.

Upstreams are asked in order of preference: if one is slow to answer, or
fails, the next is asked too, and the first answer wins. Upstreams that keep
failing are asked last until they recover. They may use DNS-over-HTTPS
(https://), DNS-over-TLS (tls://host[:853]), DNS-over-QUIC (quic://host[:853],
experimental), or plain DNS (udp://host[:53], tcp://host[:53], or just host).

DoH requires TLS unless --plaintext is set, for running behind a reverse proxy
or load balancer that terminates TLS. Certificates come from files, reloaded
when they change, or are obtained automatically from Let's Encrypt (or another
ACME certificate authority) with --acme-domain. Apple configuration profiles
are signed with that certificate, so devices can show them as verified, or with
--profile-signing-cert and --profile-signing-key.

With --dns-listen, plain DNS is also served over UDP and TCP, so any device can
use the server as its resolver. With --dns-listen and no TLS or --plaintext
setting, only plain DNS is served.

Profiles group devices under their own policy: protections (DNS rebinding,
look-alike domains, newly registered domains, tunneling, bypass methods),
blocklists, allowed and denied domains, safe search, and local rewrites. They
live in a policy file in --data-dir, created with secure defaults on first run,
and can be changed by hand, through the admin API and web UI on --admin-listen,
or with "doh profile", "doh allow", and "doh deny". Devices choose a profile by
address, or over DoH by path: /dns-query/{profile}/{device}. A server can follow
another server's policy with --policy https://.../api/v1/policy.

Settings are read from, in increasing order of precedence: a JSON --config
file, DOH_* environment variables (e.g. DOH_TLS_CERT for --tls-cert, with
commas separating lists), and flags.

Examples:
  # Behind a TLS-terminating proxy, forwarding to Quad9 over DNS-over-TLS
  doh serve --plaintext --listen :8080 --upstream tls://dns.quad9.net

  # Public server with an automatic Let's Encrypt certificate
  doh serve --acme-domain doh.example.com --acme-email admin@example.com

  # With your own certificate, forwarding to a local resolver
  doh serve --tls-cert cert.pem --tls-key key.pem --upstream 192.168.1.1

  # Local network resolver: plain DNS in, encrypted DNS out
  doh serve --dns-listen :53

  # ...with the web UI and admin API, and the router answering for .lan
  doh serve --dns-listen :53 --admin-listen localhost:9090 --forward lan=192.168.1.1

  # Phones and laptops anywhere: DoH and DoT, a profile per host name
  doh serve --acme-domain dns.example.com --dot-listen :853 --admin-listen localhost:9090
  doh setup kids --device tablet

  # A home resolver following the policy of a server in the cloud
  doh serve --dns-listen :53 --policy https://doh.example.com:9090/api/v1/policy --policy-token-file reader.token`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := flags.load()
			if err != nil {
				return err
			}
			if config.DataDir == "" {
				config.DataDir = serve.DefaultDataDir()
			}

			logger, err := config.Log.Logger()
			if err != nil {
				return err
			}

			server, err := serve.New(config, logger)
			if err != nil {
				return err
			}

			return server.ListenAndServe(cmd.Context())
		},
	}

	flags = defineServeFlags(cmd.Flags())
	return cmd
}

// load builds the serve config from the config file, then environment
// variables, then flags, each overriding the last.
func (f serveFlags) load() (serve.Config, error) {
	var config serve.Config

	// An explicit --config, even an empty one, overrides DOH_CONFIG.
	path, err := f.fs.GetString("config")
	if err != nil {
		return config, err
	}
	if !f.fs.Changed("config") {
		path = os.Getenv(envName("config"))
	}
	if path != "" {
		if err := config.LoadFile(path); err != nil {
			return config, err
		}
	}

	// Environment variables count as flags the user didn't set explicitly.
	var errs []error
	for _, o := range serveOptions {
		if f.fs.Changed(o.name) {
			continue
		}

		if value, ok := os.LookupEnv(envName(o.name)); ok {
			if err := f.fs.Set(o.name, value); err != nil {
				errs = append(errs, fmt.Errorf("invalid %s: %w", envName(o.name), err))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return config, err
	}

	for _, o := range serveOptions {
		if f.fs.Changed(o.name) {
			f.apply[o.name](&config)
		}
	}

	// The SMTP password has no flag, so it never shows in a process
	// listing: it's read once from the environment, and removed from it,
	// so nothing the server starts inherits it.
	if p, ok := os.LookupEnv(serve.SMTPPasswordEnv); ok {
		config.Alerts.SMTP.Password = alerts.Secret(p)
		_ = os.Unsetenv(serve.SMTPPasswordEnv)
	}

	return config, nil
}

// envName returns the environment variable for a flag name.
func envName(flag string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
}
