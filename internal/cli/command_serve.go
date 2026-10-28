package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/picatz/doh/internal/serve"
	"github.com/picatz/doh/pkg/doh"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// envPrefix prefixes the environment variable for each serve flag, such
// that --tls-cert can also be set with DOH_TLS_CERT.
const envPrefix = "DOH_"

// serveFlags maps each serve flag to the config field it sets.
var serveFlags = map[string]setter{
	"listen":           stringFlag(func(c *serve.Config) *string { return &c.Listen }),
	"path":             stringFlag(func(c *serve.Config) *string { return &c.Path }),
	"upstream":         sliceFlag(func(c *serve.Config) *[]string { return &c.Upstreams }),
	"tls-cert":         stringFlag(func(c *serve.Config) *string { return &c.TLS.CertFile }),
	"tls-key":          stringFlag(func(c *serve.Config) *string { return &c.TLS.KeyFile }),
	"acme-domain":      sliceFlag(func(c *serve.Config) *[]string { return &c.TLS.ACME.Domains }),
	"acme-email":       stringFlag(func(c *serve.Config) *string { return &c.TLS.ACME.Email }),
	"acme-cache-dir":   stringFlag(func(c *serve.Config) *string { return &c.TLS.ACME.CacheDir }),
	"acme-directory":   stringFlag(func(c *serve.Config) *string { return &c.TLS.ACME.DirectoryURL }),
	"acme-http-listen": stringFlag(func(c *serve.Config) *string { return &c.TLS.ACME.HTTPListen }),
	"log-level":        stringFlag(func(c *serve.Config) *string { return &c.Log.Level }),
	"log-format":       stringFlag(func(c *serve.Config) *string { return &c.Log.Format }),
	"plaintext": func(fs *pflag.FlagSet, name string, c *serve.Config) (err error) {
		c.Plaintext, err = fs.GetBool(name)
		return err
	},
	"timeout": func(fs *pflag.FlagSet, name string, c *serve.Config) error {
		d, err := fs.GetDuration(name)
		c.Timeout = serve.Duration(d)
		return err
	},
}

// setter copies the value of the named flag into a config field.
type setter func(fs *pflag.FlagSet, name string, c *serve.Config) error

func stringFlag(field func(*serve.Config) *string) setter {
	return func(fs *pflag.FlagSet, name string, c *serve.Config) (err error) {
		*field(c), err = fs.GetString(name)
		return err
	}
}

func sliceFlag(field func(*serve.Config) *[]string) setter {
	return func(fs *pflag.FlagSet, name string, c *serve.Config) (err error) {
		*field(c), err = fs.GetStringSlice(name)
		return err
	}
}

var CommandServe = &cobra.Command{
	Use:   "serve [flags]",
	Short: "Serve DNS-over-HTTPS, forwarding queries to upstream resolvers",
	Long: `Serve DNS-over-HTTPS (RFC 8484), forwarding queries to upstream resolvers.

Upstreams are tried in order until one answers, and may use DNS-over-HTTPS
(https://), DNS-over-TLS (tls://host[:853]), or plain DNS (udp://host[:53],
tcp://host[:53], or just host).

TLS is required unless --plaintext is set, for running behind a reverse proxy
or load balancer that terminates TLS. Certificates come from files, reloaded
when they change, or are obtained automatically from Let's Encrypt (or another
ACME certificate authority) with --acme-domain.

Settings are read from, in increasing order of precedence: a JSON --config
file, DOH_* environment variables (e.g. DOH_TLS_CERT for --tls-cert, with
commas separating lists), and flags.

Examples:
  # Behind a TLS-terminating proxy, forwarding to Quad9 over DNS-over-TLS
  doh serve --plaintext --listen :8080 --upstream tls://dns.quad9.net

  # Public server with an automatic Let's Encrypt certificate
  doh serve --acme-domain doh.example.com --acme-email admin@example.com

  # With your own certificate, forwarding to a local resolver
  doh serve --tls-cert cert.pem --tls-key key.pem --upstream 192.168.1.1`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		config, err := loadServeConfig(cmd.Flags())
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

// loadServeConfig builds the serve config from the config file, then
// environment variables, then flags, each overriding the last.
func loadServeConfig(fs *pflag.FlagSet) (serve.Config, error) {
	var config serve.Config

	path, err := fs.GetString("config")
	if err != nil {
		return config, err
	}
	if path == "" {
		path = os.Getenv(envName("config"))
	}
	if path != "" {
		if err := config.LoadFile(path); err != nil {
			return config, err
		}
	}

	var errs []error
	fs.VisitAll(func(f *pflag.Flag) {
		if _, ok := serveFlags[f.Name]; !ok || f.Changed {
			return
		}

		value, ok := os.LookupEnv(envName(f.Name))
		if !ok {
			return
		}

		if err := fs.Set(f.Name, value); err != nil {
			errs = append(errs, fmt.Errorf("invalid %s: %w", envName(f.Name), err))
		}
	})
	if err := errors.Join(errs...); err != nil {
		return config, err
	}

	for name, set := range serveFlags {
		if fs.Changed(name) {
			if err := set(fs, name, &config); err != nil {
				return config, fmt.Errorf("invalid --%s: %w", name, err)
			}
		}
	}

	return config, nil
}

// envName returns the environment variable for a flag name.
func envName(flag string) string {
	return envPrefix + strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
}

func init() {
	defineServeFlags(CommandServe.Flags())

	CommandRoot.AddCommand(CommandServe)
}

// defineServeFlags defines the serve flags on fs.
func defineServeFlags(fs *pflag.FlagSet) {
	fs.String("config", "", "path to a JSON config file")
	fs.String("listen", serve.DefaultListen, "address to listen on (default :8080 with --plaintext)")
	fs.String("path", doh.DefaultPath, "URI path of the DoH endpoint")
	fs.StringSlice("upstream", serve.DefaultUpstreams, "upstream resolvers, tried in order")
	fs.Duration("timeout", serve.DefaultTimeout, "maximum time to answer each query")
	fs.String("tls-cert", "", "TLS certificate chain file (PEM)")
	fs.String("tls-key", "", "TLS private key file (PEM)")
	fs.StringSlice("acme-domain", nil, "domains to obtain ACME certificates for, enabling ACME")
	fs.String("acme-email", "", "contact email for the ACME account")
	fs.String("acme-cache-dir", "", "directory for ACME accounts and certificates (default user cache dir)")
	fs.String("acme-directory", "", "ACME directory URL (default Let's Encrypt)")
	fs.String("acme-http-listen", "", "address to answer ACME HTTP-01 challenges on, such as :80")
	fs.Bool("plaintext", false, "serve unencrypted HTTP, behind a TLS-terminating proxy")
	fs.String("log-level", "info", "log level: debug, info, warn, or error")
	fs.String("log-format", "text", "log format: text or json")
}
