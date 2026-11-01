package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/client"
	"github.com/picatz/doh/internal/signin"
	"github.com/spf13/cobra"
)

// newPeopleCommand returns "doh people".
func newPeopleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "people",
		Short: "List and remove who can sign in to the web UI with passkeys",
		Long: `List and remove the people who can sign in to a doh server's web UI with
passkeys, and their passkeys. People are added by adding a passkey in the UI.

People and passkeys can be named by ID or, when it's unique, by name.

Once anyone has a passkey, sign-in links from "doh ui" need a passkey to
finish. If every passkey is lost, remove everyone with the admin token: links
then sign in on their own again, so you can add new passkeys.

Examples:
  doh people list
  doh people remove-passkey Alice "Old phone"
  doh people remove Bob`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newPeopleListCommand(), newPeopleRemoveCommand(), newPeopleRemovePasskeyCommand())
	return cmd
}

func newPeopleListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List people and their passkeys",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		people, err := c.People(cmd.Context())
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), people)
		}

		if len(people) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), `No one has a passkey yet. Sign in with "doh ui" and add one in the web UI's Security view.`)
			return nil
		}

		tw := newTable(cmd.OutOrStdout())
		fmt.Fprintln(tw, "ID\tNAME\tROLE\tPASSKEYS\tLAST USED")
		for _, p := range people {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.ID, p.Name, p.Role, passkeyNames(p.Passkeys), ago(lastUsed(p.Passkeys), time.Now()))
		}
		return tw.Flush()
	}
	return cmd
}

// passkeyNames lists passkeys by name, marking synced ones.
func passkeyNames(passkeys []signin.Passkey) string {
	if len(passkeys) == 0 {
		return "-"
	}
	names := make([]string, len(passkeys))
	for i, k := range passkeys {
		names[i] = k.Name
		if k.Synced {
			names[i] += " (synced)"
		}
	}
	return strings.Join(names, ", ")
}

// lastUsed returns when any of passkeys was last used.
func lastUsed(passkeys []signin.Passkey) time.Time {
	var last time.Time
	for _, k := range passkeys {
		if k.LastUsed.After(last) {
			last = k.LastUsed
		}
	}
	return last
}

// ago describes how long before now t was, coarsely, or "never".
func ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute") + " ago"
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour") + " ago"
	default:
		return plural(int(d/(24*time.Hour)), "day") + " ago"
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func newPeopleRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "remove <person>",
		Short:        "Remove a person and their passkeys, signing them out",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		person, err := findPerson(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		if err := c.DeletePerson(cmd.Context(), person.ID); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removed %s and their %s.\n", person.Name, plural(len(person.Passkeys), "passkey"))
		return nil
	}
	return cmd
}

func newPeopleRemovePasskeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "remove-passkey <person> <passkey>",
		Short:        "Remove one of a person's passkeys",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		person, err := findPerson(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		passkey, err := find(person.Passkeys, args[1], "passkey", "doh people list", func(k signin.Passkey) (string, string) { return k.ID, k.Name })
		if err != nil {
			return err
		}
		if err := c.DeletePasskey(cmd.Context(), person.ID, passkey.ID); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removed %s's passkey %s.\n", person.Name, passkey.Name)
		return nil
	}
	return cmd
}

// findPerson returns the person with ID or unique name ref.
func findPerson(ctx context.Context, c *client.Client, ref string) (signin.Person, error) {
	people, err := c.People(ctx)
	if err != nil {
		return signin.Person{}, err
	}
	return find(people, ref, "person", "doh people list", func(p signin.Person) (string, string) { return p.ID, p.Name })
}

// find returns the item whose ID is ref, or else the only one named ref
// (ignoring case), describing items as kind in errors, and suggesting
// the command that lists them.
func find[T any](items []T, ref, kind, list string, key func(T) (id, name string)) (T, error) {
	var zero T
	if i := slices.IndexFunc(items, func(item T) bool { id, _ := key(item); return id == ref }); i >= 0 {
		return items[i], nil
	}

	var matches []T
	for _, item := range items {
		if _, name := key(item); strings.EqualFold(name, ref) {
			matches = append(matches, item)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return zero, fmt.Errorf("no %s with ID or name %q; see %s", kind, ref, list)
	default:
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i], _ = key(m)
		}
		return zero, fmt.Errorf("%d %ss are named %q; use an ID: %s", len(matches), kind, ref, strings.Join(ids, ", "))
	}
}
