package cli

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/client"
	"github.com/picatz/doh/internal/serviceaccount"
	"github.com/picatz/jose/pkg/dpop"
	"github.com/spf13/cobra"
)

// githubIssuer is GitHub Actions' OpenID Connect issuer.
const githubIssuer = "https://token.actions.githubusercontent.com"

// newTrustCommand returns "doh service-account trust".
func newTrustCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Let workloads use a service account with their own identity tokens",
		Long: `Manage a service account's trust rules, for workload identity federation:
automation with an identity of its own, such as a GitHub Actions job or a
Kubernetes pod, exchanges its identity provider's token for a short-lived access
token, with no stored secret.

A rule names the token's issuer, and the audience and subject it must have,
exactly; a subject may end in a "*" after a "/" or ":", such as
repo:octo/app:ref:refs/heads/*. Any --claim must match exactly too. Removing a
rule, or its account, revokes the access tokens it issued at once.`,
		Example: `  doh sa trust add CI --github-repo octo/app --audience https://dns.example.com
  doh sa trust add CI --issuer https://kubernetes.example --audience doh \
    --subject system:serviceaccount:ci:deployer
  doh sa trust list CI
  doh sa trust remove CI 3f2a9c0d1e4b5a67`,
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newTrustAddCommand(), newTrustListCommand(), newTrustRemoveCommand())
	return cmd
}

func newTrustAddCommand() *cobra.Command {
	var (
		req          api.TrustRuleRequest
		claims       []string
		githubRepo   string
		githubRef    string
		tokenLasting time.Duration
	)
	cmd := &cobra.Command{
		Use:   "add <account>",
		Short: "Trust a workload's identity tokens",
		Long: `Trust a workload's identity tokens for a service account.

--github-repo trusts a GitHub Actions workflow of that repository, on --github-ref
(refs/heads/main by default): it sets the issuer to GitHub's, and the subject
to repo:OWNER/REPO:ref:REF. Workflows need "permissions: id-token: write", and
request their token with the rule's audience.

The audience defaults to the server's admin origin, if it has one. Keys come
from the issuer's OpenID Connect discovery document, unless --jwks-url says
where; keys on another host than the issuer's need --jwks-url.

--require-dpop refuses exchanges without a DPoP proof (RFC 9449), so every
access token the rule issues is bound to a key the workload holds, and is
useless if it leaks on its own.`,
		Example: `  doh sa trust add CI --github-repo octo/app --audience https://dns.example.com
  doh sa trust add CI --github-repo octo/app --github-ref 'refs/heads/*' \
    --claim repository_id=123456789`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}
	f := addClientFlags(cmd)
	fs := cmd.Flags()
	fs.StringVar(&req.Issuer, "issuer", "", "the identity provider's issuer URL")
	fs.StringVar(&req.Audience, "audience", "", "the audience tokens must name (default: the server's admin origin)")
	fs.StringVar(&req.Subject, "subject", "", "the subject tokens must have; may end in * after a / or :")
	fs.StringArrayVar(&claims, "claim", nil, "another claim tokens must have, as name=value (repeatable)")
	fs.StringVar(&req.JWKSURL, "jwks-url", "", "where the issuer publishes its keys (default: from OpenID Connect discovery)")
	fs.StringVar(&githubRepo, "github-repo", "", "trust GitHub Actions workflows of this repository, as owner/repo")
	fs.StringVar(&githubRef, "github-ref", "refs/heads/main", "with --github-repo, the Git ref workflows must run on")
	fs.DurationVar(&tokenLasting, "token-lifetime", 0, "how long access tokens last, 1m to 1h (default 15m)")
	fs.BoolVar(&req.RequireDPoP, "require-dpop", false, "refuse exchanges without a DPoP proof, so every access token is bound to a key")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if githubRepo != "" {
			if req.Issuer != "" || req.Subject != "" {
				return fmt.Errorf("--github-repo sets the issuer and subject; leave out --issuer and --subject")
			}
			owner, repo, ok := strings.Cut(githubRepo, "/")
			if !ok || owner == "" || repo == "" || strings.ContainsAny(repo, "/: ") || strings.ContainsAny(owner, ": ") {
				return fmt.Errorf("--github-repo %q isn't owner/repo", githubRepo)
			}
			if githubRef == "" || strings.ContainsAny(githubRef, " ") {
				return fmt.Errorf("--github-ref %q isn't a Git ref, such as refs/heads/main", githubRef)
			}
			req.Issuer, req.Subject = githubIssuer, "repo:"+githubRepo+":ref:"+githubRef
		} else if cmd.Flags().Changed("github-ref") {
			return fmt.Errorf("--github-ref needs --github-repo")
		}
		if req.Issuer == "" || req.Subject == "" {
			return fmt.Errorf("say which tokens to trust, with --issuer and --subject, or --github-repo")
		}
		if len(claims) > 0 {
			req.Claims = make(map[string]string, len(claims))
			for _, c := range claims {
				name, value, ok := strings.Cut(c, "=")
				if !ok || name == "" || value == "" {
					return fmt.Errorf("--claim %q isn't name=value", c)
				}
				req.Claims[name] = value
			}
		}
		if tokenLasting != 0 {
			if tokenLasting < serviceaccount.MinTokenLifetime || tokenLasting > serviceaccount.MaxTokenLifetime || tokenLasting%time.Second != 0 {
				return fmt.Errorf("--token-lifetime is whole seconds from %v to %v", serviceaccount.MinTokenLifetime, serviceaccount.MaxTokenLifetime)
			}
			req.TokenLifetime = int(tokenLasting / time.Second)
		}

		c, err := f.client()
		if err != nil {
			return err
		}
		a, err := findAccount(cmd.Context(), c, args[0])
		if err != nil {
			return err
		}
		r, err := c.AddTrustRule(cmd.Context(), a.ID, req)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		if f.json {
			return printJSON(w, r)
		}
		fmt.Fprintf(w, "%q (%s) now trusts %s tokens for %s, with audience %s, as rule %s.\n", a.Name, a.ID, r.Issuer, r.Subject, r.Audience, r.ID)
		if r.RequireDPoP {
			fmt.Fprintf(w, "Exchange one for a DPoP-bound access token lasting %v with:\n\n  doh token exchange --account %s --subject-token-file <file> --new-dpop-key <file>\n", r.Lifetime(), a.ID)
			return nil
		}
		fmt.Fprintf(w, "Exchange one for an access token lasting %v with:\n\n  doh token exchange --account %s --subject-token-file <file>\n", r.Lifetime(), a.ID)
		return nil
	}
	return cmd
}

func newTrustListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "list <account>",
		Short:        "List a service account's trust rules",
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
		rules, err := c.TrustRules(cmd.Context(), a.ID)
		if err != nil {
			return err
		}
		w := cmd.OutOrStdout()
		if f.json {
			return printJSON(w, rules)
		}
		if len(rules) == 0 {
			fmt.Fprintf(w, "%q trusts no workloads. Add a rule with \"doh sa trust add %s\".\n", a.Name, a.ID)
			return nil
		}
		printTrustRules(w, rules)
		return nil
	}
	return cmd
}

// printTrustRules writes rules as a table.
func printTrustRules(w io.Writer, rules []serviceaccount.TrustRule) {
	tw := newTable(w)
	fmt.Fprintln(tw, "ID\tISSUER\tSUBJECT\tAUDIENCE\tCLAIMS\tTOKENS LAST\tDPOP")
	for _, r := range rules {
		claims := make([]string, 0, len(r.Claims))
		for _, name := range slices.Sorted(maps.Keys(r.Claims)) {
			claims = append(claims, name+"="+r.Claims[name])
		}
		dpop := "optional"
		if r.RequireDPoP {
			dpop = "required"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\t%s\n", r.ID, r.Issuer, r.Subject, r.Audience, cmp.Or(strings.Join(claims, ","), "-"), r.Lifetime(), dpop)
	}
	_ = tw.Flush()
}

func newTrustRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "remove <account> <rule>",
		Short:        "Remove a trust rule, revoking its access tokens at once",
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
		if err := c.DeleteTrustRule(cmd.Context(), a.ID, args[1]); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Removed trust rule %s of %q; its access tokens no longer work.\n", args[1], a.Name)
		return nil
	}
	return cmd
}

// newDPoPKeyFile makes a new DPoP key, an ECDSA P-256 key, writes it to a
// new file at path, readable only by its owner, and returns a signer of
// proofs with it.
func newDPoPKeyFile(path string) (*dpop.Signer, error) {
	key, err := client.GenerateDPoPKey()
	if err != nil {
		return nil, err
	}
	signer, err := client.NewDPoPSigner(key)
	if err != nil {
		return nil, err
	}
	pem, err := client.MarshalDPoPKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeNewFile(path, pem); err != nil {
		return nil, fmt.Errorf("writing the DPoP key: %w", err)
	}
	return signer, nil
}

// newTokenCommand returns "doh token".
func newTokenCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Get a short-lived access token for automation",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newTokenExchangeCommand())
	return cmd
}

func newTokenExchangeCommand() *cobra.Command {
	var (
		addr, account, file string
		dpopKey, newDPoPKey string
		idToken, asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "exchange",
		Short: "Exchange a workload's identity token for a service account's access token",
		Long: `Exchange a workload's identity token, such as a GitHub Actions or Kubernetes
token, for a short-lived access token of a service account that trusts it
(see "doh sa trust"), and print the access token. It needs no API token.

The identity token is read from --subject-token-file, or standard input with
"-". Use the access token as DOH_TOKEN.

With --dpop-key (DOH_DPOP_KEY_FILE), or a key --new-dpop-key makes, the exchange
carries a DPoP proof (RFC 9449), and the access token is bound to that key: it
works only with proofs signed by it, so use it with the same DOH_DPOP_KEY_FILE.
A key is a PEM file: ECDSA P-256, Ed25519, or RSA.`,
		Example: `  export DOH_TOKEN="$(doh token exchange --account abcdefghijklmnop --subject-token-file id.jwt)"
  doh status

  # Bound to a new key, made for this job
  export DOH_DPOP_KEY_FILE="$RUNNER_TEMP/dpop.pem"
  export DOH_TOKEN="$(doh token exchange --account abcdefghijklmnop --subject-token-file id.jwt \
    --new-dpop-key "$DOH_DPOP_KEY_FILE")"
  doh status`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
	}
	fs := cmd.Flags()
	fs.StringVar(&addr, "addr", cmp.Or(os.Getenv(envAddr), client.DefaultAddr), "admin API address of the doh server ("+envAddr+")")
	fs.StringVar(&account, "account", "", "the ID of the service account to act as")
	fs.StringVar(&file, "subject-token-file", "", "file holding the identity token, or - for standard input")
	fs.BoolVar(&idToken, "id-token", false, "send the token as an OpenID Connect ID token, not a plain JWT")
	fs.BoolVar(&asJSON, "json", false, "print the whole token response as JSON")
	fs.StringVar(&dpopKey, "dpop-key", os.Getenv(envDPoPKeyFile), "PEM file of a DPoP key to bind the access token to ("+envDPoPKeyFile+")")
	fs.StringVar(&newDPoPKey, "new-dpop-key", "", "make a new DPoP key in this new file, readable only by you, and bind the access token to it")
	_ = cmd.MarkFlagRequired("account")
	_ = cmd.MarkFlagRequired("subject-token-file")
	cmd.RunE = func(cmd *cobra.Command, args []string) (err error) {
		var b []byte
		if file == "-" {
			b, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64<<10))
		} else {
			b, err = os.ReadFile(file)
		}
		if err != nil {
			return fmt.Errorf("reading the identity token: %w", err)
		}
		subject := strings.TrimSpace(string(b))
		if subject == "" {
			return fmt.Errorf("the identity token in %s is empty", cmp.Or(file, "standard input"))
		}
		req := api.TokenExchangeRequest{SubjectToken: subject, Audience: account}
		if idToken {
			req.SubjectTokenType = api.TokenTypeIDToken
		}

		c := &client.Client{Addr: addr}
		switch {
		case newDPoPKey != "" && cmd.Flags().Changed("dpop-key"):
			return fmt.Errorf("--new-dpop-key makes the DPoP key; leave out --dpop-key")
		case newDPoPKey != "":
			if c.DPoP, err = newDPoPKeyFile(newDPoPKey); err != nil {
				return err
			}
			// A key no token is bound to is no use.
			defer func() {
				if err != nil {
					_ = os.Remove(newDPoPKey)
				}
			}()
		case dpopKey != "":
			if c.DPoP, err = readDPoPKey(dpopKey); err != nil {
				return err
			}
		}

		tr, err := c.ExchangeToken(cmd.Context(), req)
		if err != nil {
			return err
		}
		if asJSON {
			return printJSON(cmd.OutOrStdout(), tr)
		}
		fmt.Fprintln(cmd.OutOrStdout(), tr.AccessToken)
		return nil
	}
	return cmd
}
