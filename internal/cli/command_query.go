package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/picatz/doh/pkg/dj"
	"github.com/picatz/doh/pkg/doh"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type result struct {
	Server string       `json:"server"`
	Resp   *dj.Response `json:"resp"`
}

// newHTTPClient returns a new HTTP client, or an error if one occurs.
func newHTTPClient(retryMax int, insecureSkipVerify bool) (*http.Client, error) {
	retryClient := retryablehttp.NewClient()

	retryClient.RetryMax = retryMax

	retryClient.HTTPClient = cleanhttp.DefaultClient()

	retryClient.Logger = nil // TODO: consider logger

	if insecureSkipVerify {
		transport := cleanhttp.DefaultTransport()

		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}

		retryClient.HTTPClient.Transport = transport
	}

	retryClient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}

	retryClient.Backoff = func(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
		return retryablehttp.DefaultBackoff(min, max, attemptNum, resp)
	}

	retryClient.ErrorHandler = func(resp *http.Response, err error, numTries int) (*http.Response, error) {
		return nil, err
	}

	httpClient := retryClient.StandardClient()

	return httpClient, nil
}

var CommandQuery = &cobra.Command{
	Use:   "query domains... [flags]",
	Short: "Query DNS records from DoH servers",
	Long: `Query DNS records from DoH servers using the given domains and record type.
		
Users can specify which servers to use for the query, or use the default servers from Google, Cloudflare, and Quad9.
They can also specify a timeout for the query, which defaults to 30 seconds if not specified. Each server is queried
in parallel, and each domain is queried in parallel. Results are streamed to STDOUT as JSON newline delimited objects,
which can be piped to other commands (e.g. jq) or redirected to a file.`,
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

		httpClient, err := newHTTPClient(retryMax, insecureSkipVerify)
		if err != nil {
			return fmt.Errorf("error creating http client: %w", err)
		}

		resolverAddr, err := cmd.Flags().GetString("resolver-addr")
		if err != nil {
			return fmt.Errorf("invalid resolver address: %w", err)
		}

		resolverNetwork, err := cmd.Flags().GetString("resolver-network")
		if err != nil {
			return fmt.Errorf("invalid resolver network: %w", err)
		}

		if resolverAddr != "" {
			dialer := &net.Dialer{
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

			httpClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}
		}

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

			for _, server := range servers {
				server := strings.TrimSpace(server)
				eg.Go(func() error {
					resp, err := doh.SimpleQuery(gtx, httpClient, server, req)
					if err != nil {
						return err
					}

					return output.Encode(&result{
						Server: server,
						Resp:   resp,
					})
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
	CommandQuery.Flags().StringSlice("servers", defaultServers, "servers to query")
	CommandQuery.Flags().Duration("timeout", 30*time.Second, "timeout for query, 0s for no timeout")
	CommandQuery.Flags().String("resolver-addr", "", "address of a DNS resolver to use for resolving DoH server names (e.g. 8.8.8.8:53)")
	CommandQuery.Flags().String("resolver-network", "udp", "protocol to use for resolving DoH server names (e.g. udp, tcp)")
	CommandQuery.Flags().Int("retry-max", 10, "maximum number of retries for each query")
	CommandQuery.Flags().BoolP("insecure-skip-verify", "k", false, "allow insecure server connections (e.g. self-signed TLS certificates)")

	CommandRoot.AddCommand(CommandQuery)
}
