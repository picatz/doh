package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/spf13/cobra"
)

// newBlocklistCommand returns the "doh blocklist" command.
func newBlocklistCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "blocklist",
		Short: "Inspect the blocklists doh serve can use",
	}
	cmd.AddCommand(newBlocklistCheckCommand(), newBlocklistPresetsCommand())
	return cmd
}

// newBlocklistCheckCommand returns the "doh blocklist check" command.
func newBlocklistCheckCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check names... [flags]",
		Short: "Report whether names are blocked, and by which rule",
		Long: `Report whether names are blocked by the given blocklists, and by which rule,
as JSON lines. Lists are downloaded (or read from the cache doh serve uses) as
they would be by doh serve --blocklist.

Examples:
  doh blocklist check ads.example.com
  doh blocklist check doubleclick.net --blocklist oisd-big --blocklist stevenblack`,
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := cmd.Flags()

			names, _ := flags.GetStringSlice("blocklist")
			block, _ := flags.GetStringSlice("block-domain")
			allow, _ := flags.GetStringSlice("allow-domain")

			var sources []blocklist.Source
			for _, name := range names {
				src, err := blocklist.ParseSource(name)
				if err != nil {
					return err
				}
				sources = append(sources, src)
			}

			loader := &blocklist.Loader{
				Client: &http.Client{Timeout: time.Minute},
				Logger: slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelWarn})),
			}
			if dir, err := os.UserCacheDir(); err == nil {
				loader.CacheDir = filepath.Join(dir, "doh", "blocklists")
			}

			list, err := loader.Load(cmd.Context(), sources, block, allow)
			if err != nil {
				return err
			}

			type rule struct {
				Domain     string `json:"domain"`
				Subdomains bool   `json:"subdomains"`
				Allow      bool   `json:"allow"`
			}

			out := json.NewEncoder(cmd.OutOrStdout())
			for _, name := range args {
				v := list.Lookup(name)

				result := struct {
					Name    string `json:"name"`
					Blocked bool   `json:"blocked"`
					Rule    *rule  `json:"rule,omitempty"`
					Source  string `json:"source,omitempty"`
				}{Name: name, Blocked: v.Blocked, Source: v.Source}

				if v.Rule.Domain != "" {
					result.Rule = &rule{Domain: v.Rule.Domain, Subdomains: v.Rule.Subdomains, Allow: v.Rule.Allow}
				}

				if err := out.Encode(result); err != nil {
					return err
				}
			}

			return nil
		},
	}

	fs := cmd.Flags()
	fs.StringSlice("blocklist", []string{"default"}, "lists to check: presets, URLs, or files, as [name=]location")
	fs.StringSlice("block-domain", nil, "also block these domains and their subdomains")
	fs.StringSlice("allow-domain", nil, "never block these domains and their subdomains")
	return cmd
}

// newBlocklistPresetsCommand returns the "doh blocklist presets" command.
func newBlocklistPresetsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "presets",
		Short: "List the preset blocklists",
		Long: `List the preset blocklists, by category: security lists block malware,
phishing, scams, and abuse; privacy lists block ads and trackers; parental
lists block content some households restrict. Name them with doh serve
--blocklist, in a profile's lists, or with "doh profile set".

REFRESH is how often doh serve checks each list for changes by default
(--blocklist-refresh and --blocklist-refresh-category change it): security
lists every two hours, since their sources publish several times a day, and
others daily. Checking an unchanged list costs one conditional request.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tCATEGORY\tREFRESH\tLIST\tURL")
			schedule := blocklist.DefaultRefreshSchedule()
			for _, p := range blocklist.Catalog {
				name := p.Name
				if name == blocklist.DefaultPreset {
					name += " (default)"
				}
				every := schedule.Interval(blocklist.Source{Name: p.Name, Location: p.URL})
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, p.Category, shortDuration(every), p.Title, p.URL)
			}
			return w.Flush()
		},
	}
}

// shortDuration formats d as hours or minutes, such as "2h" or "90m".
func shortDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return fmt.Sprintf("%dm", d/time.Minute)
}
