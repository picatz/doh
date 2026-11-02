package cli

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/api"
	"github.com/spf13/cobra"
)

// newAlertsCommand returns "doh alerts".
func newAlertsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "Get told when a threat is blocked, a device appears, or lookups fail",
		Long: `Send alerts to a webhook, or to an ntfy topic for push notifications on phones,
when something on the network needs someone:

  threat        a query was blocked by a security protection or list
  new-device    a device doh hasn't seen before started using it
  failing       lookups are failing: 20 or more errors, and 10% or more of
                queries, in 5 minutes
  list-failed   a blocklist didn't load (the server's operator only)

The same alert is sent at most once an hour, and bursts are summarized. Every
kind is on once there's a destination. During quiet hours, only threats are
sent; the rest wait until they end, summarized.

A tenant's admins manage their tenant's alerts, which only ever concern its
own profiles; the operator manages its own, and with --tenant, any tenant's.
Alerts send query names to their destinations, so managing them takes a
person who's an admin, or the operator's token, never a service account.

Destinations must use https. A tenant's must be on the internet: doh won't
send them to its own network. Webhook deliveries are signed as the Standard
Webhooks specification describes (https://www.standardwebhooks.com/), with a
secret shown once, when the webhook is added.`,
		Example: `  doh alerts add-ntfy https://ntfy.sh/smith-family-7f3a
  doh alerts add-webhook https://hooks.example.com/doh --name "Home Assistant"
  doh alerts set kinds=threat,new-device quiet=22:00-07:00 tz=America/New_York
  doh alerts test
  doh alerts show
  doh alerts remove 3f2a9c0d1e4b5a67`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(
		newAlertsShowCommand(),
		newAlertsSetCommand(),
		newAlertsAddCommand(alerts.Webhook),
		newAlertsAddCommand(alerts.Ntfy),
		newAlertsRemoveCommand(),
		newAlertsTestCommand(),
	)
	return cmd
}

// addTenantFlag adds --tenant, for the operator to name a tenant.
func addTenantFlag(cmd *cobra.Command) *string {
	return cmd.Flags().String("tenant", "", "the tenant whose alerts to manage (operators only; a tenant's admins always manage their own)")
}

func newAlertsShowCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "show",
		Aliases:      []string{"list"},
		Short:        "Show alert settings, destinations, and recent deliveries",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	tenant := addTenantFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		a, err := c.Alerts(cmd.Context(), *tenant)
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), a)
		}
		printAlerts(cmd.OutOrStdout(), a, time.Now())
		return nil
	}
	return cmd
}

// printAlerts describes a scope's alerts.
func printAlerts(w io.Writer, a *api.Alerts, now time.Time) {
	if a.Tenant != "" {
		fmt.Fprintf(w, "Alerts for the %s tenant\n\n", a.Tenant)
	} else {
		fmt.Fprint(w, "Alerts for this server\n\n")
	}

	tw := newTable(w)
	sending := "nothing (turn kinds on with \"doh alerts set kinds=all\")"
	if len(a.Settings.Kinds) > 0 {
		sending = kindNames(a.Settings.Kinds)
		if off := slices.DeleteFunc(slices.Clone(a.AvailableKinds), func(k alerts.Kind) bool { return slices.Contains(a.Settings.Kinds, k) }); len(off) > 0 {
			sending += " (off: " + kindNames(off) + ")"
		}
	}
	fmt.Fprintf(tw, "Sending:\t%s\n", sending)
	quiet := "off"
	if q := a.Settings.QuietHours; q != nil {
		quiet = fmt.Sprintf("%s to %s, %s: only threats are sent; the rest wait until %s", q.Start, q.End, cmp.Or(a.Settings.TimeZone, "UTC"), q.End)
	}
	fmt.Fprintf(tw, "Quiet hours:\t%s\n", quiet)
	_ = tw.Flush()

	fmt.Fprintln(w)
	if len(a.Destinations) == 0 {
		fmt.Fprintln(w, `No destinations yet, so nothing is sent. Add one with "doh alerts add-ntfy https://ntfy.sh/<topic>" or "doh alerts add-webhook <url>".`)
		return
	}
	tw = newTable(w)
	fmt.Fprintln(tw, "ID\tTYPE\tNAME\tURL\tLAST SENT\tLAST FAILED")
	for _, d := range a.Destinations {
		failed := "-"
		if !d.LastFailure.IsZero() {
			failed = ago(d.LastFailure, now) + ": " + d.LastError
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Type, cmp.Or(d.Name, "-"), d.URL, ago(d.LastSuccess, now), failed)
	}
	_ = tw.Flush()

	if len(a.Deliveries) == 0 {
		return
	}
	fmt.Fprintln(w, "\nRecent deliveries")
	tw = newTable(w)
	fmt.Fprintln(tw, "TIME\tKIND\tSUMMARY\tDESTINATION\tRESULT")
	for _, d := range a.Deliveries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ago(d.Time, now), d.Kind, d.Summary, d.Destination, deliveryResult(d))
	}
	_ = tw.Flush()
}

// deliveryResult says how a delivery went.
func deliveryResult(d alerts.Delivery) string {
	if d.OK {
		if d.Attempts > 1 {
			return fmt.Sprintf("✓ delivered (after %d tries)", d.Attempts)
		}
		return "✓ delivered"
	}
	return "✗ " + d.Error
}

// kindNames joins kinds.
func kindNames(kinds []alerts.Kind) string {
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	return strings.Join(names, ", ")
}

func newAlertsSetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set key=value...",
		Short: "Choose which alerts are sent, and quiet hours",
		Long: `Change alert settings:

  kinds=threat,new-device   which kinds to send: any of threat, new-device,
                            failing, and list-failed, or all, or none
  quiet=22:00-07:00         quiet hours, when only threats are sent; off to
                            turn them off
  tz=America/New_York       the IANA time zone quiet hours follow; without
                            one, quiet hours follow the first profile's time
                            zone, or UTC`,
		Example: `  doh alerts set kinds=all
  doh alerts set kinds=threat,failing quiet=21:30-06:30 tz=Europe/London
  doh alerts set quiet=off`,
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	tenant := addTenantFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		// "All" is every kind this tenant, or the operator, can have.
		available := func() ([]alerts.Kind, error) {
			a, err := c.Alerts(cmd.Context(), *tenant)
			if err != nil {
				return nil, err
			}
			return a.AvailableKinds, nil
		}
		patch, err := alertsPatch(args, available)
		if err != nil {
			return err
		}
		a, err := c.PatchAlerts(cmd.Context(), *tenant, patch)
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), a)
		}
		printAlerts(cmd.OutOrStdout(), a, time.Now())
		return nil
	}
	return cmd
}

// alertsPatch turns "doh alerts set" arguments into a merge patch of the
// settings, asking available for the kinds "all" means if it's used.
func alertsPatch(args []string, available func() ([]alerts.Kind, error)) (map[string]any, error) {
	patch := map[string]any{}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !ok || key == "" {
			return nil, fmt.Errorf("%q isn't key=value, such as kinds=threat,new-device", arg)
		}
		name := map[string]string{"kinds": "kinds", "kind": "kinds", "quiet": "quiet_hours", "quiet_hours": "quiet_hours", "tz": "time_zone", "time_zone": "time_zone"}[key]
		if name == "" {
			return nil, fmt.Errorf("unknown setting %q: use kinds, quiet, or tz", key)
		}
		if _, dup := patch[name]; dup {
			return nil, fmt.Errorf("%s is set twice", key)
		}

		switch name {
		case "kinds":
			switch strings.ToLower(value) {
			case "all":
				kinds, err := available()
				if err != nil {
					return nil, err
				}
				patch[name] = kinds
			case "none", "":
				patch[name] = []alerts.Kind{}
			default:
				var kinds []alerts.Kind
				for k := range strings.SplitSeq(value, ",") {
					kind := alerts.Kind(strings.ToLower(strings.TrimSpace(k)))
					if !kind.Valid() {
						return nil, fmt.Errorf("unknown kind of alert %q: use %s, all, or none", k, kindNames(alerts.Kinds))
					}
					kinds = append(kinds, kind)
				}
				patch[name] = kinds
			}
		case "quiet_hours":
			switch strings.ToLower(value) {
			case "off", "none", "":
				patch[name] = nil
			default:
				start, end, ok := strings.Cut(value, "-")
				if !ok {
					return nil, fmt.Errorf("quiet=%s: give a start and end, such as quiet=22:00-07:00", value)
				}
				patch[name] = alerts.QuietHours{Start: strings.TrimSpace(start), End: strings.TrimSpace(end)}
			}
		case "time_zone":
			if value == "" {
				patch[name] = nil
			} else {
				patch[name] = value
			}
		}
	}
	return patch, nil
}

func newAlertsAddCommand(t alerts.DestinationType) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "add-" + string(t) + " URL",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	switch t {
	case alerts.Webhook:
		cmd.Short = "Send alerts to a webhook, as signed JSON"
		cmd.Long = `Send alerts to a webhook: a JSON POST, signed as the Standard Webhooks
specification describes (https://www.standardwebhooks.com/), with the
webhook-id, webhook-timestamp, and webhook-signature headers.

The signing secret, whsec_ and a base64 key, is shown only now. Use it to
verify each delivery; doh never shows it again.`
		cmd.Example = `  doh alerts add-webhook https://hooks.example.com/doh --name "Home Assistant"`
	case alerts.Ntfy:
		cmd.Short = "Send alerts to an ntfy topic, for push notifications on phones"
		cmd.Long = `Send alerts to an ntfy topic (https://ntfy.sh), for push notifications on
phones: subscribe to the topic in the ntfy app. Anyone who knows a topic on a
public server can read it, so choose one that's hard to guess, or use a
server of your own with access control: https://user:password@... works.`
		cmd.Example = `  doh alerts add-ntfy https://ntfy.sh/smith-family-7f3a --name "Family phones"`
	}
	f := addClientFlags(cmd)
	tenant := addTenantFlag(cmd)
	name := cmd.Flags().String("name", "", "what the destination is, such as \"Mom's phone\"")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		d, err := c.AddAlertDestination(cmd.Context(), *tenant, api.AlertDestinationRequest{Type: t, URL: args[0], Name: *name})
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		if f.json {
			return printJSON(w, d)
		}
		fmt.Fprintf(w, "Added %s %s, %s.\n", t, d.Destination.ID, d.Destination.URL)
		if d.Secret != "" {
			fmt.Fprintf(w, "\nIts signing secret, shown only now:\n\n  %s\n\nVerify each delivery's webhook-signature with it, as the Standard Webhooks\nspecification describes.\n", d.Secret)
		}
		fmt.Fprintln(w, `Send a test with "doh alerts test".`)
		return nil
	}
	return cmd
}

func newAlertsRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "remove ID",
		Short:        "Stop sending alerts to a destination",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	tenant := addTenantFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		if err := c.RemoveAlertDestination(cmd.Context(), *tenant, args[0]); err != nil {
			return err
		}
		if !f.json {
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s; no more alerts go there.\n", args[0])
		}
		return nil
	}
	return cmd
}

func newAlertsTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "test",
		Short:        "Send a test alert to every destination",
		Long:         "Send a test alert to every destination, now, whatever the settings and quiet hours, and say how each went.",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	tenant := addTenantFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		res, err := c.TestAlerts(cmd.Context(), *tenant)
		if err != nil {
			return err
		}
		failed := 0
		for _, d := range res.Deliveries {
			if !d.OK {
				failed++
			}
		}
		if f.json {
			if err := printJSON(cmd.OutOrStdout(), res); err != nil {
				return err
			}
		} else {
			for _, d := range res.Deliveries {
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %s\n", d.Destination, deliveryResult(d))
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d of %d test alerts weren't delivered", failed, len(res.Deliveries))
		}
		return nil
	}
	return cmd
}
