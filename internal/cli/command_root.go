package cli

import "github.com/spf13/cobra"

var CommandRoot = &cobra.Command{
	Use:   "doh",
	Short: `doh is a CLI for querying DNS records from DoH servers`,
}
