package serve

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/filter"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/internal/rdap"
)

// baselineLoadTimeout bounds how long New waits for the Blocklist
// settings' lists to load.
const baselineLoadTimeout = 2 * time.Minute

// configurePolicy loads the blocklists and policy, and compiles the first
// engine.
//
// Without profiles, a single default profile applies the Blocklist
// settings, so "doh serve --blocklist default" behaves as it always has.
func (s *Server) configurePolicy(ctx context.Context) error {
	s.lists = blocklist.NewRegistry(&blocklist.Loader{
		Client:   &http.Client{Timeout: time.Minute},
		CacheDir: s.config.Blocklist.CacheDir,
		Logger:   s.logger,
	}, s.logger)

	b := s.config.Blocklist
	s.baseline = filter.Baseline{Lists: b.Sources, Allow: b.Allow, Deny: b.Block}
	if b.Response != "" {
		s.baseline.BlockResponse = b.Response
	}

	// Load the baseline lists first, failing as before if none load.
	if len(b.Sources) > 0 {
		var sources []blocklist.Source
		for _, src := range b.Sources {
			parsed, _ := blocklist.ParseSource(src) // validated
			sources = append(sources, parsed)
		}
		s.lists.Sync(sources)

		ctx, cancel := context.WithTimeout(ctx, baselineLoadTimeout)
		defer cancel()
		if err := s.lists.Wait(ctx, sources...); err != nil {
			return fmt.Errorf("serve: loading blocklists: %w", err)
		}

		var errs []error
		for _, src := range sources {
			if err := s.lists.Err(src); err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) == len(sources) {
			return errors.Join(errs...)
		}
	}

	p := &policy.Policy{Version: policy.Version, Profiles: []policy.Profile{{ID: policy.DefaultProfile}}}

	if s.config.policyEnabled() {
		s.store = &policyStore{
			path:   s.config.policyPath(),
			logger: s.logger,
		}
		if s.config.policyRemote() {
			s.store.remote = s.config.Policy.Source
			s.store.tokenFile = s.config.Policy.TokenFile
			s.store.refresh = time.Duration(s.config.Policy.Refresh)
			s.store.client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: refuseRedirects}
		}

		var err error
		if p, err = s.store.load(ctx); err != nil {
			return err
		}

		if s.config.DataDir != "" {
			s.ages = &rdap.Ages{
				Client: &rdap.Client{BootstrapURL: s.config.RDAP.BootstrapURL},
				Path:   filepath.Join(s.config.DataDir, "rdap.json"),
				Logger: s.logger,
			}
		}
	}

	return s.applyPolicy(p)
}

// refuseRedirects keeps a policy fetch from following redirects, which
// could send its bearer token elsewhere.
func refuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("policy: refusing to follow a redirect")
}

// applyPolicy compiles p and makes it the current policy, starting to load
// any new lists it uses.
func (s *Server) applyPolicy(p *policy.Policy) error {
	engine, err := filter.New(p, filter.Options{
		Lists:    s.lists,
		Ages:     s.ages,
		State:    s.state,
		Exempt:   s.exempt,
		Local:    s.forwardDomains(),
		Baseline: s.baseline,
	})
	if err != nil {
		return err
	}

	s.lists.Sync(engine.Sources())
	s.engine.Store(engine)
	return nil
}

// forwardDomains returns the forward zones' domains.
func (s *Server) forwardDomains() []string {
	domains := make([]string, 0, len(s.forwardZones))
	for d := range s.forwardZones {
		domains = append(domains, d)
	}
	return domains
}

// configureQueryLog opens the query log, kept in the data directory if
// there is one, and in memory otherwise.
func (s *Server) configureQueryLog() error {
	c := s.config.QueryLog
	if c.Disabled {
		return nil
	}

	opts := querylog.Options{Memory: c.Memory, Retention: time.Duration(c.Retention), Logger: s.logger}
	if s.config.DataDir != "" {
		opts.Dir = filepath.Join(s.config.DataDir, "querylog")
	}

	l, err := querylog.Open(opts)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	s.qlog = l
	return nil
}

// tokens are the admin API's credentials, kept as SHA-256 digests so
// comparisons take the same time whatever is presented.
type tokens struct {
	admin, reader [][sha256.Size]byte
}

// role is what a token may do.
type role int

const (
	roleNone   role = iota
	roleReader      // GET requests
	roleAdmin       // everything
)

// roleOf returns what token may do.
func (t tokens) roleOf(token string) role {
	if token == "" {
		return roleNone
	}
	sum := sha256.Sum256([]byte(token))

	// Check every token, so timing doesn't reveal which kind matched.
	r := roleNone
	for _, a := range t.admin {
		if subtle.ConstantTimeCompare(sum[:], a[:]) == 1 {
			r = roleAdmin
		}
	}
	for _, rd := range t.reader {
		if subtle.ConstantTimeCompare(sum[:], rd[:]) == 1 && r == roleNone {
			r = roleReader
		}
	}
	return r
}

// enabled reports whether any token is configured.
func (t tokens) enabled() bool { return len(t.admin) > 0 }

// configureTokens loads the admin API's tokens, generating them in the
// data directory if they don't exist yet.
func (s *Server) configureTokens() error {
	add := func(dst *[][sha256.Size]byte, name string, generate bool, prefix string) error {
		token, err := readToken(name)
		if errors.Is(err, fs.ErrNotExist) && generate {
			if token, err = generateToken(name, prefix); err == nil {
				s.logger.Info("admin: generated API token", slog.String("path", name))
			}
		}
		if err != nil {
			return fmt.Errorf("serve: admin token: %w", err)
		}
		*dst = append(*dst, sha256.Sum256([]byte(token)))
		return nil
	}

	if f := s.config.Admin.TokenFile; f != "" {
		if err := add(&s.tokens.admin, f, false, ""); err != nil {
			return err
		}
	}
	if s.config.DataDir == "" {
		return nil
	}
	if s.config.Admin.TokenFile == "" {
		if err := add(&s.tokens.admin, filepath.Join(s.config.DataDir, AdminTokenFile), true, "doh_admin_"); err != nil {
			return err
		}
	}
	return add(&s.tokens.reader, filepath.Join(s.config.DataDir, ReaderTokenFile), true, "doh_read_")
}

// generateToken writes a new random token to name, readable only by its
// owner. The prefix makes leaked tokens easy to recognize and scan for.
func generateToken(name, prefix string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := prefix + base64.RawURLEncoding.EncodeToString(b[:])

	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(token + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return token, err
}
