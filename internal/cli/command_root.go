// Package cli implements the doh command: querying DNS-over-HTTPS servers,
// serving DNS, and managing a running server.
package cli

import "github.com/spf13/cobra"

// New returns the doh command, with every subcommand.
//
// Each call builds a new command tree, so flags set in one run, such as in
// a test, never carry over into another.
func New() *cobra.Command {
	root := &cobra.Command{
		Use:   "doh",
		Short: "doh is a CLI for querying and serving DNS over HTTPS (DoH)",
	}
	root.AddCommand(
		newQueryCommand(),
		newServeCommand(),
		newBlocklistCommand(),
		newDoctorCommand(),
	)
	root.AddCommand(clientCommands()...)
	return root
}
