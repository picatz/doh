package serve

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
)

// policyFileInterval is how often the policy file is checked for changes
// made by hand.
const policyFileInterval = 2 * time.Second

// maxPolicySize bounds a policy file or remote policy.
const maxPolicySize = 8 << 20

// policyStore loads, saves, and watches the policy: a local file the
// server owns, or another server's policy, followed read-only.
type policyStore struct {
	// path is the policy file, or for a remote policy, where the last
	// copy is cached so restarts work offline.
	path string

	// remote, if set, is the URL of another server's policy endpoint.
	remote    string
	tokenFile string
	refresh   time.Duration
	client    *http.Client

	logger *slog.Logger

	mu      sync.Mutex
	modTime time.Time // of path, when last loaded or saved
	etag    string    // of the remote policy, when last fetched
	updated time.Time
	err     error
}

// readOnly reports whether the policy can't be changed through the API.
func (st *policyStore) readOnly() bool { return st.remote != "" }

// source describes where the policy comes from.
func (st *policyStore) source() string {
	if st.remote != "" {
		return st.remote
	}
	return st.path
}

// status describes the store, for the status endpoint.
func (st *policyStore) status() api.PolicyStatus {
	st.mu.Lock()
	defer st.mu.Unlock()

	s := api.PolicyStatus{Source: st.source(), ReadOnly: st.readOnly(), Updated: st.updated}
	if st.err != nil {
		s.Error = st.err.Error()
	}
	return s
}

func (st *policyStore) setErr(err error) {
	st.mu.Lock()
	st.err = err
	st.mu.Unlock()
}

// load returns the initial policy. A missing local file is created with
// [policy.Defaults], so there's always a file to edit; an invalid one is
// an error, rather than being silently replaced. A remote policy that
// can't be fetched falls back to its cached copy, then to the defaults.
func (st *policyStore) load(ctx context.Context) (*policy.Policy, error) {
	if st.remote != "" {
		p, err := st.fetch(ctx)
		switch {
		case err == nil:
			return p, nil
		case p != nil:
			return p, nil // not modified since the cached copy
		}

		st.logger.WarnContext(ctx, "policy: fetching remote policy failed", slog.String("url", st.remote), slog.Any("error", err))
		st.setErr(err)
		if p, cerr := st.readFile(); cerr == nil {
			st.logger.WarnContext(ctx, "policy: using cached copy of remote policy", slog.String("path", st.path))
			return p, nil
		}
		st.logger.WarnContext(ctx, "policy: no cached copy; using defaults until the remote policy can be fetched")
		return policy.Defaults(), nil
	}

	p, err := st.readFile()
	if errors.Is(err, fs.ErrNotExist) {
		p = policy.Defaults()
		if err := st.save(p); err != nil {
			return nil, err
		}
		st.logger.InfoContext(ctx, "policy: created a policy with secure defaults; edit it, or change it through the admin API", slog.String("path", st.path))
		return p, nil
	}
	return p, err
}

// readFile reads and validates the policy file.
func (st *policyStore) readFile() (*policy.Policy, error) {
	f, err := os.Open(st.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(io.LimitReader(f, maxPolicySize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPolicySize {
		return nil, fmt.Errorf("policy: %s exceeds %d bytes", st.path, maxPolicySize)
	}

	p, err := policy.Unmarshal(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", st.path, err)
	}

	st.mu.Lock()
	st.modTime, st.updated, st.err = info.ModTime(), time.Now(), nil
	st.mu.Unlock()
	return p, nil
}

// save writes p to the policy file atomically, readable only by its
// owner, since it describes the network's devices.
func (st *policyStore) save(p *policy.Policy) error {
	b, err := policy.Marshal(p)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(st.path, b, 0o600); err != nil {
		return fmt.Errorf("policy: saving %s: %w", st.path, err)
	}

	if info, err := os.Stat(st.path); err == nil {
		st.mu.Lock()
		st.modTime, st.updated, st.err = info.ModTime(), time.Now(), nil
		st.mu.Unlock()
	}
	return nil
}

// watch calls apply with each new policy until ctx is done: when the file
// changes on disk, or the remote policy changes. Invalid policies are
// logged and ignored, keeping the current one.
func (st *policyStore) watch(ctx context.Context, apply func(*policy.Policy) error) error {
	interval := policyFileInterval
	if st.remote != "" {
		interval = st.refresh
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		var (
			p   *policy.Policy
			err error
		)
		if st.remote != "" {
			p, err = st.fetch(ctx)
			if err == nil && p == nil {
				continue
			}
		} else {
			info, serr := os.Stat(st.path)
			st.mu.Lock()
			unchanged := serr == nil && info.ModTime().Equal(st.modTime)
			st.mu.Unlock()
			if unchanged || errors.Is(serr, fs.ErrNotExist) {
				continue
			}
			p, err = st.readFile()
		}

		if err == nil {
			err = apply(p)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			st.setErr(err)
			st.logger.WarnContext(ctx, "policy: reload failed, keeping the current policy", slog.String("source", st.source()), slog.Any("error", err))
			continue
		}
		st.logger.InfoContext(ctx, "policy: reloaded", slog.String("source", st.source()), slog.Int("profiles", len(p.Profiles)))
	}
}

// fetch fetches the remote policy, revalidating with its entity tag. It
// returns a nil policy and error if it hasn't changed since the last
// fetch, and caches each new policy in the policy file.
func (st *policyStore) fetch(ctx context.Context) (*policy.Policy, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, st.remote, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "doh (+https://github.com/picatz/doh)")

	if st.tokenFile != "" {
		token, err := readToken(st.tokenFile)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	st.mu.Lock()
	if st.etag != "" {
		req.Header.Set("If-None-Match", st.etag)
	}
	st.mu.Unlock()

	resp, err := st.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy: fetching %s: %w", st.remote, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		st.mu.Lock()
		st.updated, st.err = time.Now(), nil
		st.mu.Unlock()
		return nil, nil
	default:
		return nil, fmt.Errorf("policy: fetching %s: %s", st.remote, resp.Status)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize+1))
	if err != nil {
		return nil, fmt.Errorf("policy: fetching %s: %w", st.remote, err)
	}
	if len(b) > maxPolicySize {
		return nil, fmt.Errorf("policy: %s exceeds %d bytes", st.remote, maxPolicySize)
	}

	p, err := policy.Unmarshal(b)
	if err != nil {
		return nil, fmt.Errorf("policy: from %s: %w", st.remote, err)
	}

	if err := st.save(p); err != nil {
		st.logger.WarnContext(ctx, "policy: caching remote policy", slog.Any("error", err))
	}

	st.mu.Lock()
	st.etag, st.updated, st.err = resp.Header.Get("ETag"), time.Now(), nil
	st.mu.Unlock()
	return p, nil
}

// readToken reads a bearer token from a file, trimming whitespace.
func readToken(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("reading token: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("reading token: %s is empty", name)
	}
	return token, nil
}

// writeFileAtomic writes data to name through a temporary file in the
// same directory, renamed into place, so readers never see a partial
// file.
func writeFileAtomic(name string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(name)+"."+hex.EncodeToString(suffix[:])+".tmp")

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewReader(data))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, name)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
