package cli

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/picatz/doh/internal/audit"
	"github.com/spf13/cobra"
)

// newAuditCommand returns "doh audit".
func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show who changed what on a doh server, and when",
		Long: `Show the audit trail of a running doh server, newest first: every change made
through its admin API (profiles, allowed and denied names, apps, tenants,
people, service accounts and their keys, alerts, and sign-in and setup links),
who made it, and for whom.

A tenant's admins see their own tenant's trail, including changes the
operator made to it. The operator sees every tenant's, or one's with --tenant.
Reading it takes an admin. The trail is kept for --audit-retention (a year by
default) in the server's data directory, and never holds a secret.

Examples:
  # Who unblocked TikTok?
  doh audit --action profile.updated --json | jq 'select(.details["services.removed"] | contains("tiktok")?)'

  # Everything one person did, since a date
  doh audit --actor Kent --before 2026-11-01T00:00:00Z

  # Every service account change, as JSON lines
  doh audit --action service_account --all --json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	fs := cmd.Flags()
	tenant := fs.String("tenant", "", "only this tenant's changes (operators only; a tenant's admins always see their own)")
	actor := fs.String("actor", "", "only changes by this actor: a person's or service account's ID or name, or admin for the operator's token")
	action := fs.String("action", "", "only this action, or those under it: profile matches profile.updated and profile.created")
	before := fs.String("before", "", "only changes before this time (RFC 3339, such as 2026-11-02T15:04:05Z)")
	n := fs.IntP("lines", "n", 50, fmt.Sprintf("number of changes to print (at most %d per request)", audit.MaxLimit))
	all := fs.Bool("all", false, "print every matching change, page by page")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if *n < 1 {
			return errors.New("--lines must be at least 1")
		}
		q := url.Values{}
		for k, v := range map[string]string{"actor": *actor, "action": *action, "before": *before} {
			if v != "" {
				q.Set(k, v)
			}
		}
		if cmd.Flags().Changed("tenant") {
			q.Set("tenant", *tenant)
		}
		q.Set("limit", strconv.Itoa(min(*n, audit.MaxLimit)))

		c, err := f.client()
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		enc := json.NewEncoder(out) // JSON lines, for jq
		printed := 0
		for {
			page, err := c.Audit(cmd.Context(), q)
			if err != nil {
				return err
			}
			for _, e := range page.Events {
				if !*all && printed == *n {
					return nil
				}
				if f.json {
					err = enc.Encode(e)
				} else {
					err = printAuditEvent(out, e, time.Now())
				}
				if err != nil {
					return err
				}
				printed++
			}
			if page.NextPageToken == "" || !*all && printed >= *n {
				break
			}
			q.Set("page_token", page.NextPageToken)
		}
		if printed == 0 && !f.json {
			fmt.Fprintln(out, "No changes match.")
		}
		return nil
	}
	return cmd
}

// printAuditEvent prints one change: when, who, and what, then its
// details, indented.
func printAuditEvent(w io.Writer, e audit.Event, now time.Time) error {
	who := cmp.Or(e.Actor.Name, e.Actor.ID, string(e.Actor.Kind))
	if e.Actor.Tenant != "" {
		who += " (" + e.Actor.Tenant + ")"
	}
	what := cmp.Or(e.Summary, e.Action)
	if e.Tenant != "" && e.Tenant != e.Actor.Tenant {
		what += " [tenant " + e.Tenant + "]"
	}
	if _, err := fmt.Fprintf(w, "%s  %s  %s\n", e.Time.Local().Format("2006-01-02 15:04:05"), who, what); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "    %s", e.Action)
	if e.Actor.Via != "" {
		fmt.Fprintf(&b, ", by %s", e.Actor.Via)
	}
	fmt.Fprintf(&b, ", %s\n", ago(e.Time, now))
	for _, k := range slices.Sorted(maps.Keys(e.Details)) {
		fmt.Fprintf(&b, "    %s: %s\n", k, e.Details[k])
	}
	_, err := io.WriteString(w, b.String())
	return err
}
