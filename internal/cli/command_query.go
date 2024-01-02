package cli

import (
	"context"
	"encoding/json"
	"fmt"
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

	CommandRoot.AddCommand(CommandQuery)
}
