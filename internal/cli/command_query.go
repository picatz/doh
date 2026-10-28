package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/picatz/doh/internal/httpretry"
	"github.com/picatz/doh/internal/upstream"
	"github.com/picatz/doh/pkg/dj"
	"github.com/picatz/doh/pkg/doh"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type result struct {
	Server string       `json:"server"`
	TLS    *tlsInfo     `json:"tls,omitempty"`
	Resp   *dj.Response `json:"resp"`
}

// tlsInfo describes the TLS connection a query used.
type tlsInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	ALPN        string `json:"alpn,omitempty"`
}

func newTLSInfo(state tls.ConnectionState) *tlsInfo {
	return &tlsInfo{
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
	}
}

// newTransport returns a clone of [http.DefaultTransport], optionally
// skipping TLS certificate verification.
func newTransport(insecureSkipVerify bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if insecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	return transport
}

var CommandQuery = &cobra.Command{
	Use:   "query domains... [flags]",
	Short: "Query DNS records from DoH servers",
	Long: `Query DNS records from DoH servers using the given domains and record type.

Users can specify which servers to use for the query, or use the default servers from Google, Cloudflare, and Quad9.
Servers can use DNS-over-HTTPS (https://, or http:// for a local server), DNS-over-TLS (tls://host[:853]), or plain
DNS (udp://host[:53], tcp://host[:53], or just host), the same forms doh serve accepts as upstreams. They can also
specify a timeout for the query, which defaults to 30 seconds if not specified. Each server is queried in parallel,
and each domain is queried in parallel. Results are streamed to STDOUT as JSON newline delimited objects, including
the TLS version, cipher suite, and ALPN protocol for encrypted servers, which can be piped to other commands (e.g. jq)
or redirected to a file.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		servers, err := cmd.Flags().GetStringSlice("servers")
		if err != nil {
			return fmt.Errorf("invalid servers: %w", err)
		}

		queryType := cmd.Flag("type").Value.String()

		timeout, err := cmd.Flags().GetDuration("timeout")
		if err != nil {
			return fmt.Errorf("invalid timeout: %w", err)
		}

		retryMax, err := cmd.Flags().GetInt("retry-max")
		if err != nil {
			return fmt.Errorf("invalid retry max: %w", err)
		}

		insecureSkipVerify, err := cmd.Flags().GetBool("insecure-skip-verify")
		if err != nil {
			return fmt.Errorf("invalid insecure skip verify: %w", err)
		}

		transport := newTransport(insecureSkipVerify)

		resolverAddr, err := cmd.Flags().GetString("resolver-addr")
		if err != nil {
			return fmt.Errorf("invalid resolver address: %w", err)
		}

		resolverNetwork, err := cmd.Flags().GetString("resolver-network")
		if err != nil {
			return fmt.Errorf("invalid resolver network: %w", err)
		}

		opts := upstream.Options{Timeout: timeout}

		if insecureSkipVerify {
			opts.TLSConfig = &tls.Config{InsecureSkipVerify: true}
		}

		if resolverAddr != "" {
			opts.Dialer = &net.Dialer{
				Resolver: &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{
							Timeout: timeout,
						}
						conn, err := d.DialContext(ctx, resolverNetwork, resolverAddr)
						if err != nil {
							return nil, fmt.Errorf("error dialing with custom resolver: %w", err)
						}
						return conn, nil
					},
				},
			}

			transport.DialContext = opts.Dialer.DialContext

			// A proxy would resolve DoH server names itself, silently
			// bypassing the custom resolver, so connect directly instead.
			transport.Proxy = nil
		}

		opts.HTTPClient = &http.Client{
			Transport: &httpretry.Transport{
				Base:       transport,
				MaxRetries: retryMax,
			},
			CheckRedirect: upstream.CheckRedirect,
		}

		exchangers := make(map[string]upstream.Exchanger, len(servers))
		for _, server := range servers {
			server = strings.TrimSpace(server)
			e, err := upstream.Parse(server, opts)
			if err != nil {
				return fmt.Errorf("invalid server: %w", err)
			}
			exchangers[server] = e
		}

		// Results are written concurrently, so serialize them.
		var outputMu sync.Mutex
		output := json.NewEncoder(cmd.OutOrStdout())

		var (
			ctx    context.Context    = cmd.Context()
			cancel context.CancelFunc = func() {}
		)

		if timeout != 0 {
			ctx, cancel = context.WithTimeout(cmd.Context(), timeout)
		}

		defer cancel()

		eg, gtx := errgroup.WithContext(ctx)

		for _, arg := range args {
			req := &dj.Request{
				Name: arg,
				Type: queryType,
			}

			for server, e := range exchangers {
				eg.Go(func() error {
					var state atomic.Pointer[tls.ConnectionState]
					qctx := upstream.WithTLSObserver(gtx, func(s tls.ConnectionState) { state.Store(&s) })

					msg, err := e.Exchange(qctx, req.Msg())
					if err != nil {
						return err
					}

					r := &result{Server: server, Resp: dj.NewResponse(msg)}
					if s := state.Load(); s != nil {
						r.TLS = newTLSInfo(*s)
					}

					outputMu.Lock()
					defer outputMu.Unlock()
					return output.Encode(r)
				})
			}
		}

		if err := eg.Wait(); err != nil {
			return fmt.Errorf("encountered error while querying: %w", err)
		}

		return nil
	},
}

func init() {
	defaultServers := []string{
		doh.Google,
		doh.Cloudflare,
		doh.Quad9,
	}

	CommandQuery.Flags().String("type", "A", "dns record type to query for each domain, such as A, AAAA, MX, etc.")
	CommandQuery.Flags().StringSlice("servers", defaultServers, "servers to query: https://, http://, tls://, udp://, tcp://, or host")
	CommandQuery.Flags().Duration("timeout", 30*time.Second, "timeout for query, 0s for no timeout")
	CommandQuery.Flags().String("resolver-addr", "", "address of a DNS resolver to use for resolving DoH server names (e.g. 8.8.8.8:53); connects directly, ignoring HTTP(S)_PROXY")
	CommandQuery.Flags().String("resolver-network", "udp", "protocol to use for resolving DoH server names (e.g. udp, tcp)")
	CommandQuery.Flags().Int("retry-max", 10, "maximum number of retries for each DoH query")
	CommandQuery.Flags().BoolP("insecure-skip-verify", "k", false, "allow insecure server connections (e.g. self-signed TLS certificates)")

	CommandRoot.AddCommand(CommandQuery)
}
