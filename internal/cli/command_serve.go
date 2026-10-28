package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

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
	option((*pflag.FlagSet).String, "path", doh.DefaultPath, "URI path of the DoH endpoint",
		func(c *serve.Config, v string) { c.Path = v }),
	option((*pflag.FlagSet).StringSlice, "upstream", serve.DefaultUpstreams, "upstream resolvers, tried in order",
		func(c *serve.Config, v []string) { c.Upstreams = v }),
	option((*pflag.FlagSet).Duration, "timeout", serve.DefaultTimeout, "maximum time to answer each query",
		func(c *serve.Config, v time.Duration) { c.Timeout = serve.Duration(v) }),
	option((*pflag.FlagSet).String, "tls-cert", "", "TLS certificate chain file (PEM)",
		func(c *serve.Config, v string) { c.TLS.CertFile = v }),
	option((*pflag.FlagSet).String, "tls-key", "", "TLS private key file (PEM)",
		func(c *serve.Config, v string) { c.TLS.KeyFile = v }),
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

var CommandServe = &cobra.Command{
	Use:   "serve [flags]",
	Short: "Serve DNS-over-HTTPS, forwarding queries to upstream resolvers",
	Long: `Serve DNS-over-HTTPS (RFC 8484), forwarding queries to upstream resolvers.

Upstreams are tried in order until one answers, and may use DNS-over-HTTPS
(https://), DNS-over-TLS (tls://host[:853]), or plain DNS (udp://host[:53],
tcp://host[:53], or just host).

DoH requires TLS unless --plaintext is set, for running behind a reverse proxy
or load balancer that terminates TLS. Certificates come from files, reloaded
when they change, or are obtained automatically from Let's Encrypt (or another
ACME certificate authority) with --acme-domain.

With --dns-listen, plain DNS is also served over UDP and TCP, so any device can
use the server as its resolver. With --dns-listen and no TLS or --plaintext
setting, only plain DNS is served.

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
  doh serve --dns-listen :53`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := commandServeFlags.load()
		if err != nil {
			return err
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

	return config, nil
}

// envName returns the environment variable for a flag name.
func envName(flag string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
}

// commandServeFlags are the flags of [CommandServe].
var commandServeFlags serveFlags

func init() {
	commandServeFlags = defineServeFlags(CommandServe.Flags())

	CommandRoot.AddCommand(CommandServe)
}
