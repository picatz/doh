package cli

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/client"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/internal/serve"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/spf13/cobra"
)

// Environment variables the client commands read, in the style of
// VAULT_ADDR and VAULT_TOKEN.
const (
	envAddr        = "DOH_ADDR"
	envToken       = "DOH_TOKEN"
	envTokenFile   = "DOH_TOKEN_FILE"
	envDPoPKeyFile = "DOH_DPOP_KEY_FILE"
)

// dpopKeySuffix names the file beside a key's secret file that holds the
// DPoP private key it's bound to.
const dpopKeySuffix = ".dpop"

// clientFlags are the connection flags every client command shares.
type clientFlags struct {
	addr, token, tokenFile, dpopKey string
	json                            bool
}

// defaultTokenFile is where doh serve writes its admin token by default.
func defaultTokenFile() string {
	dir := serve.DefaultDataDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, serve.AdminTokenFile)
}

// addClientFlags adds the connection and output flags to cmd, with
// defaults from the environment.
func addClientFlags(cmd *cobra.Command) *clientFlags {
	f := &clientFlags{}
	fs := cmd.Flags()
	fs.StringVar(&f.addr, "addr", cmp.Or(os.Getenv(envAddr), client.DefaultAddr), "admin API address of the doh server ("+envAddr+")")
	fs.StringVar(&f.token, "token", os.Getenv(envToken), "API token ("+envToken+")")
	fs.StringVar(&f.tokenFile, "token-file", cmp.Or(os.Getenv(envTokenFile), defaultTokenFile()), "file to read the API token from if --token isn't set ("+envTokenFile+")")
	fs.StringVar(&f.dpopKey, "dpop-key", os.Getenv(envDPoPKeyFile), "PEM file of the DPoP key a bound token needs, to sign each request with; defaults to the token file's "+dpopKeySuffix+" sibling, if there is one ("+envDPoPKeyFile+")")
	fs.BoolVar(&f.json, "json", false, "print JSON instead of text")
	return f
}

// client returns an API client for the flags, reading the token file if
// no token was given, and the DPoP key, if there is one.
func (f *clientFlags) client() (*client.Client, error) {
	token := strings.TrimSpace(f.token)
	dpopKey := f.dpopKey
	if token == "" && f.tokenFile != "" {
		b, err := os.ReadFile(f.tokenFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("no API token: %s doesn't exist. doh serve writes its admin token there (in its --data-dir) on first start; run this as the same user, or pass --token or %s", f.tokenFile, envToken)
		case err != nil:
			return nil, fmt.Errorf("reading API token: %w", err)
		}
		token = strings.TrimSpace(string(b))

		// A bound key's secret file has its DPoP key beside it.
		if _, err := os.Stat(f.tokenFile + dpopKeySuffix); dpopKey == "" && err == nil {
			dpopKey = f.tokenFile + dpopKeySuffix
		}
	}
	c := &client.Client{Addr: f.addr, Token: token}
	if dpopKey != "" {
		signer, err := readDPoPKey(dpopKey)
		if err != nil {
			return nil, err
		}
		c.DPoP = signer
	}
	return c, nil
}

// readDPoPKey reads a DPoP key from the PEM file at path.
func readDPoPKey(path string) (*dpop.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the DPoP key: %w", err)
	}
	signer, err := client.ParseDPoPKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return signer, nil
}

// writeNewFile writes data to a new file at path, readable only by its
// owner. It never overwrites, and so never follows, an existing file.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
	}
	return err
}

// printJSON writes v as indented JSON.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// newTable returns a tab writer for aligned columns.
func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

// newStatusCommand returns "doh status".
func newStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show a running doh server's status",
		Long: `Show a running doh server's status: its listeners, upstreams, policy,
blocklists, and query counts, from its admin API.

The server is found at --addr (DOH_ADDR), and authenticated with --token
(DOH_TOKEN), or the token file doh serve writes to its data directory.

Examples:
  # The local server, using its token file
  doh status

  # A remote server
  DOH_ADDR=https://doh.example.com:9090 DOH_TOKEN=... doh status`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		s, err := c.Status(cmd.Context())
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), s)
		}
		return printStatus(cmd.OutOrStdout(), s, time.Now())
	}
	return cmd
}

// printStatus writes a human-readable summary of s.
func printStatus(w io.Writer, s *api.Status, now time.Time) error {
	tw := newTable(w)
	fmt.Fprintf(tw, "Version\t%s\n", cmp.Or(s.Version, "unknown"))
	if !s.Started.IsZero() {
		fmt.Fprintf(tw, "Uptime\t%s\n", now.Sub(s.Started).Round(time.Second))
	}
	for _, kind := range slices.Sorted(maps.Keys(s.Listeners)) {
		fmt.Fprintf(tw, "Listener (%s)\t%s\n", kind, s.Listeners[kind])
	}
	fmt.Fprintf(tw, "Upstreams\t%s\n", strings.Join(s.Upstreams, ", "))

	source := cmp.Or(s.Policy.Source, "flags")
	if s.Policy.ReadOnly {
		source += " (read-only)"
	}
	fmt.Fprintf(tw, "Policy\t%s\n", source)
	fmt.Fprintf(tw, "Profiles\t%d\n", s.Policy.Profiles)
	if s.Policy.Error != "" {
		fmt.Fprintf(tw, "Policy error\t%s\n", s.Policy.Error)
	}

	if s.QueryLog.Enabled {
		fmt.Fprintf(tw, "Query log\t%d entries in memory", s.QueryLog.Entries)
		if s.QueryLog.Dir != "" {
			fmt.Fprintf(tw, ", files in %s kept %s", s.QueryLog.Dir, s.QueryLog.Retention)
		}
		fmt.Fprintln(tw)
	} else {
		fmt.Fprintf(tw, "Query log\toff\n")
	}

	if len(s.Queries) > 0 {
		var parts []string
		for _, k := range []string{"total", "blocked", "cached", "errors"} {
			if v, ok := s.Queries[k]; ok {
				parts = append(parts, fmt.Sprintf("%d %s", v, k))
			}
		}
		fmt.Fprintf(tw, "Queries\t%s\n", strings.Join(parts, ", "))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(s.Lists) == 0 {
		return nil
	}
	fmt.Fprintln(w, "\nLists:")
	tw = newTable(w)
	fmt.Fprintln(tw, "  NAME\tRULES\tSTATE")
	for _, l := range s.Lists {
		state := "loaded " + l.Loaded.Local().Format(time.DateTime)
		switch {
		case l.Error != "":
			state = "error: " + l.Error
		case l.Loading:
			state = "loading"
		case l.Loaded.IsZero():
			state = "not loaded"
		}
		fmt.Fprintf(tw, "  %s\t%d\t%s\n", l.Name, l.Rules, state)
	}
	return tw.Flush()
}

// newUICommand returns "doh ui".
func newUICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Print a sign-in link to a doh server's web UI",
		Long: `Print a single-use link that signs a browser in to a doh server's web UI.

The link expires in five minutes, and works once. Its code is in the URL's
fragment, which browsers never send to servers, so it stays out of logs; the
browser trades it for a session cookie, and never holds the API token.

Once anyone has added a passkey in the UI, a link only starts signing in:
finish with a passkey. Passkeys also sign in on their own, without a link.

Creating a link needs the admin token. --reader makes a link for a
read-only session, and --tenant a link that signs in to a tenant, such as
to invite a household's first admin (as "doh tenant invite" does).

Examples:
  doh ui
  doh ui --open
  doh ui --reader
  doh ui --tenant smiths`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	open := cmd.Flags().Bool("open", false, "open the link in a browser")
	reader := cmd.Flags().Bool("reader", false, "sign in read-only")
	tenant := cmd.Flags().String("tenant", "", "sign in to this tenant, such as to invite its first admin")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return printSigninLink(cmd, f, *reader, *tenant, *open)
	}
	return cmd
}

// printSigninLink creates a sign-in link and prints it: the link alone on
// standard output, so scripts can use it, and notes on standard error.
func printSigninLink(cmd *cobra.Command, f *clientFlags, reader bool, tenant string, open bool) error {
	c, err := f.client()
	if err != nil {
		return err
	}
	role := "admin"
	if reader {
		role = "reader"
	}
	link, err := c.SigninLink(cmd.Context(), role, tenant)
	if err != nil {
		return err
	}
	if f.json {
		return printJSON(cmd.OutOrStdout(), link)
	}

	fmt.Fprintln(cmd.OutOrStdout(), link.URL)
	note := "Single-use; expires in " + humanDuration(time.Until(link.Expires)) + "."
	if tenant != "" {
		as := "an admin"
		if reader {
			as = "a reader"
		}
		note = "Signs in to tenant " + strconv.Quote(tenant) + " as " + as + ". " + note
	}
	if link.PasskeyRequired {
		note += " Finish signing in with your passkey."
	}
	fmt.Fprintln(cmd.ErrOrStderr(), note)

	if open {
		return openBrowser(link.URL)
	}
	return nil
}

// humanDuration rounds d to whole minutes, or seconds under a minute.
func humanDuration(d time.Duration) string {
	switch {
	case d >= time.Minute:
		m := int(d.Round(time.Minute) / time.Minute)
		if m == 1 {
			return "1 minute"
		}
		return strconv.Itoa(m) + " minutes"
	case d > 0:
		return strconv.Itoa(int(d.Round(time.Second)/time.Second)) + " seconds"
	default:
		return "0 seconds"
	}
}

// openBrowser opens link with the platform's URL opener.
func openBrowser(link string) error {
	name := "xdg-open"
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", link).Start()
	}
	return exec.Command(name, link).Start()
}

// profileListKeys are the profile fields "doh profile set" always treats
// as string lists.
var profileListKeys = []string{"lists", "allow", "deny", "block_tlds", "clients", "services"}

// tenantListKeys are the tenant fields "doh tenant set" always treats as
// string lists.
var tenantListKeys = []string{"networks"}

// mergePatch turns key=value arguments with dotted keys, such as
// security.rebinding=false, into a JSON merge patch. Values of listKeys
// are always string lists.
func mergePatch(args []string, listKeys []string) (map[string]any, error) {
	patch := map[string]any{}
	for _, arg := range args {
		key, value, ok := strings.Cut(arg, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid setting %q: want key=value, such as security.rebinding=false", arg)
		}

		path := strings.Split(key, ".")
		obj := patch
		for _, part := range path[:len(path)-1] {
			if part == "" {
				return nil, fmt.Errorf("invalid key %q", key)
			}
			next, ok := obj[part].(map[string]any)
			if !ok {
				if _, exists := obj[part]; exists {
					return nil, fmt.Errorf("key %q conflicts with another setting", key)
				}
				next = map[string]any{}
				obj[part] = next
			}
			obj = next
		}
		last := path[len(path)-1]
		if last == "" {
			return nil, fmt.Errorf("invalid key %q", key)
		}
		if _, exists := obj[last]; exists {
			return nil, fmt.Errorf("key %q is set twice", key)
		}
		obj[last] = parseValue(key, value, listKeys)
	}
	return patch, nil
}

// parseValue interprets a "doh profile set" or "doh tenant set" value.
func parseValue(key, value string, listKeys []string) any {
	switch {
	case value == "":
		return nil // an empty value resets the field
	case slices.Contains(listKeys, key) || strings.Contains(value, ","):
		list := []string{}
		for v := range strings.SplitSeq(value, ",") {
			if v = strings.TrimSpace(v); v != "" {
				list = append(list, v)
			}
		}
		return list
	case value == "true":
		return true
	case value == "false":
		return false
	}
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		return n
	}
	return value
}

// newProfileCommand returns "doh profile" and its subcommands.
func newProfileCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "List, show, and change a doh server's profiles",
		Long: `List, show, and change the profiles of a running doh server.

Each profile is the policy for a group of clients: which protections are on,
which blocklists apply, and which domains are always allowed or denied.

Examples:
  doh profile list
  doh profile show default
  doh profile create kids --name "Kids' tablets"
  doh profile create smith-kids --tenant smiths
  doh profile set kids safe_search=true security.newly_registered=true
  doh profile set streaming lists=threat-intel,hagezi-pro security.newly_registered=false
  doh profile delete kids`,
	}

	list := &cobra.Command{
		Use:          "list",
		Short:        "List profiles",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	listFlags := addClientFlags(list)
	list.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := listFlags.client()
		if err != nil {
			return err
		}
		profiles, err := c.Profiles(cmd.Context())
		if err != nil {
			return err
		}
		if listFlags.json {
			return printJSON(cmd.OutOrStdout(), api.Profiles{Profiles: profiles})
		}
		// Show tenants only on servers that have them.
		tenants := slices.ContainsFunc(profiles, func(p policy.Profile) bool { return p.Tenant != "" })

		tw := newTable(cmd.OutOrStdout())
		if tenants {
			fmt.Fprintln(tw, "ID\tNAME\tTENANT\tCLIENTS\tLISTS\tPROTECTIONS")
		} else {
			fmt.Fprintln(tw, "ID\tNAME\tCLIENTS\tLISTS\tPROTECTIONS")
		}
		for _, p := range profiles {
			clients := len(p.Clients) + len(p.Devices)
			cols := []string{p.ID, cmp.Or(p.Name, "-")}
			if tenants {
				cols = append(cols, cmp.Or(p.Tenant, "-"))
			}
			cols = append(cols, strconv.Itoa(clients), cmp.Or(strings.Join(p.Lists, ","), "-"), cmp.Or(strings.Join(protections(p), ","), "-"))
			fmt.Fprintln(tw, strings.Join(cols, "\t"))
		}
		return tw.Flush()
	}

	show := &cobra.Command{
		Use:          "show <id>",
		Short:        "Show a profile",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	showFlags := addClientFlags(show)
	show.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := showFlags.client()
		if err != nil {
			return err
		}
		p, err := c.Profile(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		if showFlags.json {
			return printJSON(cmd.OutOrStdout(), p)
		}
		return printProfile(cmd.OutOrStdout(), p)
	}

	create := &cobra.Command{
		Use:          "create <id>",
		Short:        "Create a profile with no protections or lists",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	createFlags := addClientFlags(create)
	name := create.Flags().String("name", "", "human-readable name")
	tenant := create.Flags().String("tenant", "", "the tenant the profile belongs to (operators only; a tenant's profiles are always its own)")
	create.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := createFlags.client()
		if err != nil {
			return err
		}
		p, err := c.CreateProfile(cmd.Context(), policy.Profile{ID: args[0], Name: *name, Tenant: *tenant})
		if err != nil {
			return err
		}
		if createFlags.json {
			return printJSON(cmd.OutOrStdout(), p)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Created profile %q. Turn protections on with: doh profile set %s security.rebinding=true ...\n", p.ID, p.ID)
		return nil
	}

	del := &cobra.Command{
		Use:          "delete <id>",
		Short:        "Delete a profile",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	delFlags := addClientFlags(del)
	del.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := delFlags.client()
		if err != nil {
			return err
		}
		if err := c.DeleteProfile(cmd.Context(), args[0]); err != nil {
			return err
		}
		if !delFlags.json {
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted profile %q.\n", args[0])
		}
		return nil
	}

	set := &cobra.Command{
		Use:   "set <id> key=value...",
		Short: "Change a profile's settings",
		Long: `Change a profile's settings with key=value pairs, using dots for nested
fields. Values are true or false, integers, comma-separated lists, or strings;
an empty value (key=) resets a field. lists, allow, deny, block_tlds, clients,
and services are always lists, replacing the profile's current ones. Blocked
apps are services IDs from "doh services"; schedules have "doh schedule", and
time_zone names the IANA zone they run in (blank is the server's local time).

Examples:
  doh profile set kids safe_search=true security.bypass=true
  doh profile set default security.newly_registered=true security.newly_registered_days=14
  doh profile set default lists=threat-intel,hagezi-normal
  doh profile set kids name="Kids' tablets" block_response=null
  doh profile set kids services=tiktok,roblox
  doh profile set kids time_zone=America/New_York
  doh profile set kids block_tlds=   # an empty value resets a field`,
		Args:         cobra.MinimumNArgs(2),
		SilenceUsage: true,
	}
	setFlags := addClientFlags(set)
	set.RunE = func(cmd *cobra.Command, args []string) error {
		patch, err := mergePatch(args[1:], profileListKeys)
		if err != nil {
			return err
		}
		c, err := setFlags.client()
		if err != nil {
			return err
		}
		p, err := c.PatchProfile(cmd.Context(), args[0], patch)
		if err != nil {
			return err
		}
		if setFlags.json {
			return printJSON(cmd.OutOrStdout(), p)
		}
		return printProfile(cmd.OutOrStdout(), p)
	}

	cmd.AddCommand(list, show, create, del, set)
	return cmd
}

// protections returns the IDs of the protections p turns on.
func protections(p policy.Profile) []string {
	var on []string
	for _, t := range toggles(p) {
		if t.on {
			on = append(on, t.id)
		}
	}
	return on
}

type toggle struct {
	id string
	on bool
}

// toggles returns p's built-in protections, in catalog order.
func toggles(p policy.Profile) []toggle {
	s := p.Security
	return []toggle{
		{"rebinding", s.Rebinding},
		{"homograph", s.Homograph},
		{"newly_registered", s.NewlyRegistered},
		{"tunneling", s.Tunneling},
		{"bypass", s.Bypass},
		{"safe_search", p.SafeSearch},
	}
}

// printProfile writes a human-readable summary of p.
func printProfile(w io.Writer, p *policy.Profile) error {
	tw := newTable(w)
	fmt.Fprintf(tw, "ID\t%s\n", p.ID)
	if p.Name != "" {
		fmt.Fprintf(tw, "Name\t%s\n", p.Name)
	}
	for _, t := range toggles(*p) {
		state := "off"
		if t.on {
			state = "on"
			if t.id == "newly_registered" {
				state = fmt.Sprintf("on (younger than %d days)", cmp.Or(p.Security.NewlyRegisteredDays, policy.DefaultNewlyRegisteredDays))
			}
		}
		fmt.Fprintf(tw, "%s\t%s\n", t.id, state)
	}
	fmt.Fprintf(tw, "Block response\t%s\n", cmp.Or(p.BlockResponse, policy.BlockNXDomain))
	fmt.Fprintf(tw, "Logging\t%s\n", map[bool]string{false: "on", true: "off"}[p.Logging.Disabled])

	for _, row := range []struct {
		title  string
		values []string
	}{
		{"Lists", p.Lists},
		{"Allow", p.Allow},
		{"Deny", p.Deny},
		{"Blocked TLDs", p.BlockTLDs},
		{"Clients", p.Clients},
		{"Apps", serviceNames(p.Services)},
	} {
		if len(row.values) > 0 {
			fmt.Fprintf(tw, "%s\t%s\n", row.title, strings.Join(row.values, ", "))
		}
	}
	for _, d := range p.Devices {
		fmt.Fprintf(tw, "Device %s\t%s\n", d.Name, strings.Join(d.Addrs, ", "))
	}
	for _, rw := range p.Rewrites {
		fmt.Fprintf(tw, "Rewrite %s\t%s\n", rw.Name, strings.Join(rw.Addrs, ", "))
	}
	if p.TimeZone != "" || len(p.Schedules) > 0 {
		fmt.Fprintf(tw, "Time zone\t%s\n", cmp.Or(p.TimeZone, "server's local time"))
	}
	for _, sc := range p.Schedules {
		fmt.Fprintf(tw, "Schedule %s\t%s %s  %s\n", sc.Name, formatDays(sc.Days), formatPeriod(sc), describeBlocks(sc))
	}
	return tw.Flush()
}

// newDomainCommand returns "doh allow" or "doh deny".
func newDomainCommand(list string) *cobra.Command {
	verb, other := "Allow", "deny"
	if list == "deny" {
		verb, other = "Deny", "allow"
	}
	cmd := &cobra.Command{
		Use:   list + " <domain>...",
		Short: verb + " domains, and their subdomains, in a profile",
		Long: fmt.Sprintf(`%s domains, with their subdomains, in a profile of a running doh server,
removing them from the profile's %s list. With --remove, take them off the %s
list instead.

Examples:
  doh %s example.com
  doh %s example.com example.org --profile kids
  doh %s example.com --remove`, verb, other, list, list, list, list),
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	profile := cmd.Flags().String("profile", policy.DefaultProfile, "profile to change")
	remove := cmd.Flags().Bool("remove", false, "remove the domains from the "+list+" list instead")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		var p *policy.Profile
		for _, domain := range args {
			ctx := cmd.Context()
			switch {
			case list == "allow" && !*remove:
				p, err = c.Allow(ctx, *profile, domain)
			case list == "allow":
				p, err = c.Unallow(ctx, *profile, domain)
			case !*remove:
				p, err = c.Deny(ctx, *profile, domain)
			default:
				p, err = c.Undeny(ctx, *profile, domain)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", domain, err)
			}
			if !f.json {
				action := map[bool]string{false: "Added", true: "Removed"}[*remove]
				prep := map[bool]string{false: "to", true: "from"}[*remove]
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s the %s list of profile %q.\n", action, domain, prep, list, *profile)
			}
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), p)
		}
		return nil
	}
	return cmd
}

// newLogCommand returns "doh log".
func newLogCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show, search, and follow a doh server's query log",
		Long: `Show the most recent entries of a running doh server's query log, newest
last, optionally filtered, and with --follow, keep printing new ones.

Examples:
  # The last 50 queries
  doh log

  # Everything blocked for one device, as it happens
  doh log --blocked --device living-room-tv -f

  # Search names, as JSON lines for jq
  doh log -q google --json | jq -r .name`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	fs := cmd.Flags()
	follow := fs.BoolP("follow", "f", false, "keep printing new entries")
	blocked := fs.Bool("blocked", false, "only blocked queries (same as --status blocked)")
	status := fs.String("status", "", "only queries with this status: allowed, blocked, rewritten, or error")
	profile := fs.String("profile", "", "only queries from this profile")
	device := fs.String("device", "", "only queries from this device")
	clientAddr := fs.String("client", "", "only queries from this client address")
	search := fs.StringP("search", "q", "", "only names containing this text")
	n := fs.IntP("lines", "n", 50, fmt.Sprintf("number of recent entries to print first (at most %d)", querylog.MaxLimit))

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if *blocked {
			if *status != "" && *status != string(querylog.StatusBlocked) {
				return errors.New("--blocked and --status conflict")
			}
			*status = string(querylog.StatusBlocked)
		}
		filter := url.Values{}
		for k, v := range map[string]string{"status": *status, "profile": *profile, "device": *device, "client": *clientAddr, "q": *search} {
			if v != "" {
				filter.Set(k, v)
			}
		}

		c, err := f.client()
		if err != nil {
			return err
		}

		out := cmd.OutOrStdout()
		print := newLogPrinter(out, f.json, colorEnabled(out))

		if *n > 0 {
			q := url.Values{}
			for k, v := range filter {
				q[k] = v
			}
			q.Set("limit", strconv.Itoa(min(*n, querylog.MaxLimit)))
			page, err := c.Logs(cmd.Context(), q)
			if err != nil {
				return err
			}
			// Pages are newest first; print oldest first, like tail.
			for _, e := range slices.Backward(page.Entries) {
				if err := print(e); err != nil {
					return err
				}
			}
		}

		if !*follow {
			return nil
		}
		for e, err := range c.Stream(cmd.Context(), filter) {
			if err != nil {
				return err
			}
			if err := print(e); err != nil {
				return err
			}
		}
		return nil
	}
	return cmd
}

// colorEnabled reports whether w is a terminal that should get color.
func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// statusColors are ANSI colors for each log status.
var statusColors = map[querylog.Status]string{
	querylog.StatusAllowed:   "\x1b[32m",
	querylog.StatusBlocked:   "\x1b[31m",
	querylog.StatusRewritten: "\x1b[36m",
	querylog.StatusError:     "\x1b[33m",
}

// newLogPrinter returns a function printing one entry per line, as JSON or
// as aligned columns. Columns are padded to fixed widths rather than with
// a tab writer, so streamed lines appear as they arrive.
func newLogPrinter(w io.Writer, asJSON, color bool) func(querylog.Entry) error {
	if asJSON {
		enc := json.NewEncoder(w)
		return func(e querylog.Entry) error { return enc.Encode(e) }
	}

	header := false
	return func(e querylog.Entry) error {
		if !header {
			header = true
			if _, err := fmt.Fprintf(w, "%-8s  %-18s  %-9s  %-5s  %-40s  %s\n", "TIME", "CLIENT", "STATUS", "TYPE", "NAME", "REASON"); err != nil {
				return err
			}
		}
		status := fmt.Sprintf("%-9s", e.Status)
		if color {
			if c, ok := statusColors[e.Status]; ok {
				status = c + status + "\x1b[0m"
			}
		}
		reason := e.Reason
		if e.Source != "" {
			reason += " (" + e.Source + ")"
		}
		if e.Cached && reason == "" {
			reason = "cached"
		}
		_, err := fmt.Fprintf(w, "%-8s  %-18s  %s  %-5s  %-40s  %s\n",
			e.Time.Local().Format(time.TimeOnly), cmp.Or(e.Device, e.Hostname, e.Client, "-"), status, e.Type, e.Name, cmp.Or(reason, "-"))
		return err
	}
}

// newExplainCommand returns "doh explain".
func newExplainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <name>",
		Short: "Explain how a doh server answers a name, check by check",
		Long: `Explain how a running doh server would answer a query: which profile it
matches, each check it goes through, and why it's allowed, blocked, or
rewritten.

Examples:
  doh explain ads.example.com
  doh explain example.com --type AAAA --profile kids
  doh explain example.com --client 192.168.1.50`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	qtype := cmd.Flags().String("type", "A", "record type")
	profile := cmd.Flags().String("profile", "", "profile to explain for (default: the one --client matches)")
	clientAddr := cmd.Flags().String("client", "", "client address to match a profile with")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c, err := f.client()
		if err != nil {
			return err
		}
		e, err := c.Explain(cmd.Context(), args[0], *qtype, *profile, *clientAddr)
		if err != nil {
			return err
		}
		if f.json {
			return printJSON(cmd.OutOrStdout(), e)
		}
		return printExplanation(cmd.OutOrStdout(), e)
	}
	return cmd
}

// printExplanation writes a human-readable trace of e.
func printExplanation(w io.Writer, e *api.Explanation) error {
	d := e.Decision
	headline := fmt.Sprintf("%s %s: %s", e.Name, e.Type, strings.ToUpper(d.Action))
	if d.Reason != "" {
		headline += " by " + d.Reason
	}
	if d.Rule != "" {
		headline += " (" + d.Rule
		if d.Source != "" {
			headline += " from " + d.Source
		}
		headline += ")"
	}
	fmt.Fprintln(w, headline)
	if d.Detail != "" {
		fmt.Fprintln(w, "  "+d.Detail)
	}

	var who []string
	if e.Profile != "" {
		who = append(who, "profile "+e.Profile)
	}
	if e.Device != "" {
		who = append(who, "device "+e.Device)
	}
	if e.Client != "" {
		who = append(who, "client "+e.Client)
	}
	if len(who) > 0 {
		fmt.Fprintln(w, "  as "+strings.Join(who, ", "))
	}

	fmt.Fprintln(w, "\nChecks:")
	tw := newTable(w)
	for _, c := range e.Checks {
		mark := "–"
		switch c.Result {
		case api.CheckPass:
			mark = "✓"
		case api.CheckMatch:
			mark = "✗"
			if d.Action == api.ActionAllow || d.Action == api.ActionRewrite {
				mark = "●"
			}
		}
		fmt.Fprintf(tw, "  %s %s\t%s\n", mark, c.Check, c.Detail)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if e.Rcode != "" || len(e.Answers) > 0 {
		fmt.Fprintf(w, "\nAnswer: %s\n", cmp.Or(e.Rcode, "NOERROR"))
		for _, a := range e.Answers {
			fmt.Fprintln(w, "  "+a)
		}
	}
	return nil
}

// clientCommands returns every admin API client command.
func clientCommands() []*cobra.Command {
	return []*cobra.Command{
		newStatusCommand(),
		newUICommand(),
		newProfileCommand(),
		newDomainCommand("allow"),
		newDomainCommand("deny"),
		newLogCommand(),
		newExplainCommand(),
		newSetupCommand(),
		newTenantCommand(),
		newPeopleCommand(),
		newServiceAccountCommand(),
		newTokenCommand(),
		newServicesCommand(),
		newScheduleCommand(),
		newAlertsCommand(),
	}
}
