package cli

import (
	"cmp"
	"fmt"
	"strconv"
	"strings"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/spf13/cobra"
)

// newTenantCommand returns "doh tenant" and its subcommands.
func newTenantCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Share a doh server with other households, each managing their own profiles",
		Long: `List, create, change, and remove the tenants of a running doh server, and
invite their admins.

A tenant is a group of people, such as a family or friends, who share the
server but manage their own profiles, devices, query log, and people, without
seeing anyone else's. Their devices select their profiles by DoH path or host
name, or by address within the tenant's networks, which the operator assigns
and which can't overlap another tenant's. Their profiles may use preset
blocklists only, unless the tenant is allowed custom lists (HTTPS URLs).

Managing tenants needs the operator's admin token.

Examples:
  doh tenant create smiths --name "The Smiths" --network 192.168.10.0/24
  doh tenant invite smiths
  doh tenant list
  doh tenant set smiths custom_lists=true max_profiles=5
  doh tenant set smiths networks=192.168.10.0/24,fd10::/64
  doh tenant delete smiths`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(
		newTenantListCommand(),
		newTenantCreateCommand(),
		newTenantSetCommand(),
		newTenantDeleteCommand(),
		newTenantInviteCommand(),
	)
	return cmd
}

func newTenantListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List tenants",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		tenants, err := c.Tenants(cmd.Context())
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), api.Tenants{Tenants: tenants})
		}
		if len(tenants) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), `No tenants yet. Share this server with: doh tenant create <id> --name "..." --network <prefix>`)
			return nil
		}

		profiles, err := c.Profiles(cmd.Context())
		if err != nil {
			return err
		}
		counts := make(map[string]int)
		for _, p := range profiles {
			counts[p.Tenant]++
		}

		tw := newTable(cmd.OutOrStdout())
		fmt.Fprintln(tw, "ID\tNAME\tNETWORKS\tPROFILES\tCUSTOM LISTS\tMAX")
		for _, t := range tenants {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%d\n",
				t.ID, cmp.Or(t.Name, "-"), cmp.Or(strings.Join(t.Networks, ","), "-"),
				counts[t.ID], yesNo(t.CustomLists), cmp.Or(t.MaxProfiles, policy.DefaultMaxTenantProfiles))
		}
		return tw.Flush()
	}
	return cmd
}

// yesNo describes a boolean for tables.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func newTenantCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <id>",
		Short: "Create a tenant",
		Long: `Create a tenant, then invite its first admin with "doh tenant invite".

--network assigns the addresses the tenant's profiles may select devices by,
such as its home network; repeat it for several. Without any, the tenant's
devices use DoH paths or host names to select its profiles.

Examples:
  doh tenant create smiths --name "The Smiths" --network 192.168.10.0/24
  doh tenant create jones --network 192.168.20.0/24 --network fd20::/64 --custom-lists --max-profiles 5`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	name := cmd.Flags().String("name", "", "human-readable name, such as \"The Smiths\"")
	networks := cmd.Flags().StringArray("network", nil, "an address or prefix the tenant's profiles may select devices by (repeatable)")
	customLists := cmd.Flags().Bool("custom-lists", false, "let the tenant's profiles use blocklists by HTTPS URL, not only presets")
	maxProfiles := cmd.Flags().Int("max-profiles", 0, "most profiles the tenant may have (default "+strconv.Itoa(policy.DefaultMaxTenantProfiles)+")")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		t, err := c.CreateTenant(cmd.Context(), policy.Tenant{
			ID: args[0], Name: *name, Networks: *networks, CustomLists: *customLists, MaxProfiles: *maxProfiles,
		})
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), t)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created tenant %q. Invite its first admin with: doh tenant invite %s\n", t.ID, t.ID)
		return nil
	}
	return cmd
}

func newTenantSetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <id> key=value...",
		Short: "Change a tenant's settings",
		Long: `Change a tenant's settings with key=value pairs. Values are true or false,
integers, comma-separated lists, or strings; an empty value (key=) resets a
field. networks is always a list, replacing the tenant's current ones.

Examples:
  doh tenant set smiths name="The Smith family"
  doh tenant set smiths networks=192.168.10.0/24,fd10::/64
  doh tenant set smiths custom_lists=true max_profiles=5
  doh tenant set smiths networks=`,
		Args:         cobra.MinimumNArgs(2),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		patch, err := mergePatch(args[1:], tenantListKeys)
		if err != nil {
			return err
		}
		c, err := f.client()
		if err != nil {
			return err
		}
		t, err := c.PatchTenant(cmd.Context(), args[0], patch)
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), t)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Updated tenant %q.\n", t.ID)
		return nil
	}
	return cmd
}

func newTenantDeleteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a tenant and its people",
		Long: `Delete a tenant. It must have no profiles left: delete them, or move them to
another tenant, first. The tenant's people and passkeys are removed too, and
signed out.

Examples:
  doh tenant delete smiths`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		if err := c.DeleteTenant(cmd.Context(), args[0]); err != nil {
			return err
		}
		if !f.json {
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted tenant %q and signed out its people.\n", args[0])
		}
		return nil
	}
	return cmd
}

func newTenantInviteCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "invite <id>",
		Short: "Print a sign-in link for a tenant's admin",
		Long: `Print a single-use link that signs a browser in to a tenant, to invite its
first admin, or another one. Send it to them: it expires in five minutes, and
works once. Once the tenant's people have passkeys, links only start signing
in, and a passkey finishes.

The link alone goes to standard output, so scripts can use it.

Examples:
  doh tenant invite smiths
  doh tenant invite smiths --reader
  doh tenant invite smiths --open`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	open := cmd.Flags().Bool("open", false, "open the link in a browser")
	reader := cmd.Flags().Bool("reader", false, "invite a read-only person")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return printSigninLink(cmd, f, *reader, args[0], *open)
	}
	return cmd
}
