package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/picatz/doh/pkg/dj"
	"github.com/picatz/doh/pkg/doh"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

type result struct {
	Server string       `json:"server"`
	Resp   *dj.Response `json:"resp"`
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

		httpClient := cleanhttp.DefaultClient()

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

	CommandRoot.AddCommand(CommandQuery)
}
