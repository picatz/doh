package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/client"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/spf13/cobra"
)

// newServiceAccountCommand returns "doh service-account".
func newServiceAccountCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "service-account",
		Aliases: []string{"sa"},
		Short:   "Manage the identities scripts and automation use with the admin API",
		Long: `Manage service accounts: the identities scripts, home automation, CI jobs,
and other servers use with a doh server's admin API.

A service account belongs to one tenant, or to the server's operator, and is a
reader or an admin, as a person is. It authenticates with keys: secrets shown
once, when they're made, that always expire, within a year. Rotate a key to
replace it, with a grace period while automation switches over; revoke one, or
delete its account, to stop it at once. Deleting a tenant deletes its service
accounts.

Service accounts can't manage people, sign-in links, or service accounts,
including their own keys: that takes a person, or the operator's token.

Accounts can be named by ID or, when it's unique, by name; keys by ID.`,
		Example: `  doh service-account create "Home Assistant"
  doh sa create Backups --admin --secret-file backups.key
  doh sa list
  doh sa key rotate "Home Assistant" --grace 1h
  doh sa delete "Home Assistant"`,
		Args: cobra.NoArgs,
	}
	key := &cobra.Command{
		Use:   "key",
		Short: "Add, rotate, and revoke a service account's keys",
		Args:  cobra.NoArgs,
	}
	key.AddCommand(newKeyAddCommand(), newKeyRotateCommand(), newKeyRevokeCommand())
	cmd.AddCommand(newServiceAccountListCommand(), newServiceAccountCreateCommand(), newServiceAccountDeleteCommand(), key)
	return cmd
}

func newServiceAccountListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List service accounts and their keys",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		accounts, err := c.ServiceAccounts(cmd.Context())
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), accounts)
		}
		if len(accounts) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), `No service accounts yet. Make one with "doh service-account create <name>".`)
			return nil
		}
		printAccounts(cmd.OutOrStdout(), accounts, time.Now())
		return nil
	}
	return cmd
}

// printAccounts writes accounts as a table, one row per key.
func printAccounts(w io.Writer, accounts []serviceaccount.Account, now time.Time) {
	tw := newTable(w)
	fmt.Fprintln(tw, "ID\tNAME\tTENANT\tROLE\tKEY\tEXPIRES\tLAST USED")
	for _, a := range accounts {
		tenant := cmp.Or(a.Tenant, "-")
		if len(a.Keys) == 0 {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t-\t-\t-\n", a.ID, a.Name, tenant, a.Role)
			continue
		}
		id, name, role := a.ID, a.Name, string(a.Role)
		for _, k := range a.Keys {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, name, tenant, role, k.ID, expiry(k, now), ago(k.LastUsed, now))
			id, name, tenant, role = "", "", "", "" // later rows are the same account's
		}
	}
	_ = tw.Flush()
}

// expiry describes when k expires, relative to now.
func expiry(k serviceaccount.Key, now time.Time) string {
	if k.Expired(now) {
		return "expired " + k.Expires.Format(time.DateOnly)
	}
	return k.Expires.Format(time.DateOnly) + " (" + until(k.Expires, now) + ")"
}

// until describes how long after now t is, to the nearest minute, hour,
// or day, so a key made to last 90 days says "in 90 days".
func until(t, now time.Time) string {
	d := t.Sub(now)
	in := func(unit time.Duration, name string) string {
		return "in " + plural(max(1, int(d.Round(unit)/unit)), name)
	}
	switch {
	case d < time.Hour-30*time.Second:
		return in(time.Minute, "minute")
	case d < 48*time.Hour-30*time.Minute:
		return in(time.Hour, "hour")
	default:
		return in(24*time.Hour, "day")
	}
}

// secretFlags are the flags for commands that make a key.
type secretFlags struct {
	expires string
	file    string
}

func addSecretFlags(cmd *cobra.Command, s *secretFlags) {
	cmd.Flags().StringVar(&s.expires, "expires", "90d", "how long the key lasts, such as 30d or 12h; at most 366d")
	cmd.Flags().StringVar(&s.file, "secret-file", "", "write the key's secret to this new file, readable only by you, instead of printing it")
}

// lifetime parses a key lifetime: a Go duration such as 12h, or a number
// of days such as 90d.
func lifetime(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%q isn't a number of days, such as 90d", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q isn't a duration, such as 90d or 12h", s)
	}
	return d, nil
}

// check reports a problem delivering a secret before anything is made.
func (s *secretFlags) check() error {
	if s.file == "" {
		return nil
	}
	if _, err := os.Lstat(s.file); err == nil {
		return fmt.Errorf("--secret-file %s already exists; choose a new file", s.file)
	}
	return nil
}

// deliver hands over a new key's secret: written to the secret file, or
// printed with what to do with it.
func (s *secretFlags) deliver(w io.Writer, k *api.NewKey, asJSON bool) error {
	if s.file != "" {
		// O_EXCL: never overwrite, and so never follow, an existing file.
		f, err := os.OpenFile(s.file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("the key was made, but writing its secret failed, so revoke it (doh sa key revoke %s %s): %w", k.Account, k.Key.ID, err)
		}
		_, err = io.WriteString(f, k.Secret+"\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("the key was made, but writing its secret failed, so revoke it (doh sa key revoke %s %s): %w", k.Account, k.Key.ID, err)
		}
		k.Secret = "" // not printed, even as JSON
	}
	if asJSON {
		return printJSON(w, k)
	}

	now := time.Now()
	if s.file != "" {
		fmt.Fprintf(w, "Key %s written to %s. It expires %s.\n", k.Key.ID, s.file, expiry(k.Key, now))
		fmt.Fprintf(w, "Use it with doh's --token-file %s, or as a bearer token.\n", s.file)
		return nil
	}
	fmt.Fprintf(w, "Key %s, shown only now. Keep it somewhere safe, such as a secret manager:\n\n  %s\n\n", k.Key.ID, k.Secret)
	fmt.Fprintf(w, "It expires %s. Send it as a bearer token, or use it with doh as DOH_TOKEN.\n", expiry(k.Key, now))
	return nil
}

func newServiceAccountCreateCommand() *cobra.Command {
	var (
		admin  bool
		tenant string
		noKey  bool
		secret secretFlags
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Make a service account, and its first key",
		Long: `Make a service account, a reader unless --admin, and its first key, shown once.

A tenant's admins make service accounts for their own tenant; the operator may
make them for any tenant with --tenant, or for itself.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.Flags().BoolVar(&admin, "admin", false, "let it change things, not only read them")
	cmd.Flags().StringVar(&tenant, "tenant", "", "the tenant it acts for (operator only)")
	cmd.Flags().BoolVar(&noKey, "no-key", false, "make the account without a key")
	addSecretFlags(cmd, &secret)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		d, err := lifetime(secret.expires)
		if err != nil && !noKey {
			return fmt.Errorf("--expires: %w", err)
		}
		if err := secret.check(); err != nil {
			return err
		}
		c, err := f.client()
		if err != nil {
			return err
		}
		role := serviceaccount.RoleReader
		if admin {
			role = serviceaccount.RoleAdmin
		}
		a, err := c.CreateServiceAccount(cmd.Context(), api.ServiceAccountRequest{Name: args[0], Role: string(role), Tenant: tenant})
		if err != nil {
			return err
		}

		w := cmd.OutOrStdout()
		if noKey {
			if f.json {
				return printJSON(w, a)
			}
			fmt.Fprintf(w, "Made %s. Add a key with: doh sa key add %s\n", describeAccount(*a), a.ID)
			return nil
		}
		k, err := c.AddServiceAccountKey(cmd.Context(), a.ID, api.KeyRequest{Expires: time.Now().Add(d)})
		if err != nil {
			return fmt.Errorf("made service account %s, but not its key: %w", a.ID, err)
		}
		if !f.json {
			fmt.Fprintf(w, "Made %s.\n", describeAccount(*a))
		}
		return secret.deliver(w, k, f.json)
	}
	return cmd
}

// describeAccount describes a, such as `"Home Assistant" (ID), a reader
// for the smiths tenant`.
func describeAccount(a serviceaccount.Account) string {
	whose := "the server's operator"
	if a.Tenant != "" {
		whose = "the " + a.Tenant + " tenant"
	}
	article := "a"
	if a.Role == serviceaccount.RoleAdmin {
		article = "an"
	}
	return fmt.Sprintf("%q (%s), %s %s for %s", a.Name, a.ID, article, a.Role, whose)
}

func newServiceAccountDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "delete <account>",
		Short:        "Delete a service account, revoking its keys at once",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		a, err := findAccount(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := c.DeleteServiceAccount(cmd.Context(), a.ID); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted %q (%s); its %s no longer work.\n", a.Name, a.ID, plural(len(a.Keys), "key"))
		return nil
	}
	return cmd
}

func newKeyAddCommand() *cobra.Command {
	var secret secretFlags
	cmd := &cobra.Command{
		Use:          "add <account>",
		Short:        "Add a key to a service account, shown once",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	addSecretFlags(cmd, &secret)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		d, err := lifetime(secret.expires)
		if err != nil {
			return fmt.Errorf("--expires: %w", err)
		}
		if err := secret.check(); err != nil {
			return err
		}
		c, err := f.client()
		if err != nil {
			return err
		}
		a, err := findAccount(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		k, err := c.AddServiceAccountKey(cmd.Context(), a.ID, api.KeyRequest{Expires: time.Now().Add(d)})
		if err != nil {
			return err
		}
		return secret.deliver(cmd.OutOrStdout(), k, f.json)
	}
	return cmd
}

func newKeyRotateCommand() *cobra.Command {
	var (
		secret secretFlags
		grace  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "rotate <account> [key]",
		Short: "Replace a key with a new one, shown once",
		Long: `Replace a service account's key with a new one, shown once. The old key stops
working when --grace is up: at once by default, or up to a week later, so
automation can switch to the new key first.

The key may be left out when the account has only one that still works.`,
		Example: `  doh sa key rotate "Home Assistant"
  doh sa key rotate ci 3f2a9c0d1e4b5a67 --grace 1h --secret-file ci.key`,
		Args:         cobra.RangeArgs(1, 2),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	addSecretFlags(cmd, &secret)
	cmd.Flags().DurationVar(&grace, "grace", 0, "how long the old key keeps working, such as 1h; at most 168h")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		d, err := lifetime(secret.expires)
		if err != nil {
			return fmt.Errorf("--expires: %w", err)
		}
		if grace < 0 || grace > serviceaccount.MaxGrace {
			return fmt.Errorf("--grace is 0 to %v", serviceaccount.MaxGrace)
		}
		if err := secret.check(); err != nil {
			return err
		}
		c, err := f.client()
		if err != nil {
			return err
		}
		a, err := findAccount(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		key, err := pickKey(a, args[1:], time.Now())
		if err != nil {
			return err
		}

		now := time.Now()
		req := api.RotateKeyRequest{Expires: now.Add(d)}
		if grace > 0 {
			req.PreviousExpires = now.Add(grace)
		}
		k, err := c.RotateServiceAccountKey(cmd.Context(), a.ID, key, req)
		if err != nil {
			return err
		}
		if !f.json {
			if grace > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "Key %s keeps working until %s (%s).\n", key, req.PreviousExpires.Format(time.Kitchen), until(req.PreviousExpires, now))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Key %s no longer works.\n", key)
			}
		}
		return secret.deliver(cmd.OutOrStdout(), k, f.json)
	}
	return cmd
}

// pickKey returns the key ID in args, or else a's only working key.
func pickKey(a serviceaccount.Account, args []string, now time.Time) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}
	live := slices.DeleteFunc(slices.Clone(a.Keys), func(k serviceaccount.Key) bool { return k.Expired(now) })
	switch len(live) {
	case 1:
		return live[0].ID, nil
	case 0:
		return "", fmt.Errorf("%q has no working key to rotate; add one with: doh sa key add %s", a.Name, a.ID)
	default:
		ids := make([]string, len(live))
		for i, k := range live {
			ids[i] = k.ID
		}
		return "", fmt.Errorf("%q has %d working keys; say which to rotate: %s", a.Name, len(live), strings.Join(ids, ", "))
	}
}

func newKeyRevokeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "revoke <account> <key>",
		Short:        "Revoke a key at once",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		a, err := findAccount(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := c.DeleteServiceAccountKey(cmd.Context(), a.ID, args[1]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Revoked key %s of %q.\n", args[1], a.Name)
		return nil
	}
	return cmd
}

// findAccount returns the service account with ID, or the only one named,
// ref.
func findAccount(ctx context.Context, c *client.Client, ref string) (serviceaccount.Account, error) {
	accounts, err := c.ServiceAccounts(ctx)
	if err != nil {
		return serviceaccount.Account{}, err
	}
	return find(accounts, ref, "service account", "doh service-account list", func(a serviceaccount.Account) (string, string) { return a.ID, a.Name })
}
