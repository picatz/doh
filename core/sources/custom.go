package sources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"

	doh "github.com/picatz/doh/core"
	"golang.org/x/sync/semaphore"
)

// Custom is a user-provided DNS over HTTPs resolver.
type Custom struct {
	Lock *semaphore.Weighted

	userSuppliedName    string
	userSuppliedBaseURL string
}

// NewCustomSource allows for a user-provided DoH source.
func NewCustomSource(name, baseURL string) *Custom {
	return &Custom{userSuppliedName: name, userSuppliedBaseURL: baseURL}
}

// String is a custom printer for debugging purposes.
func (s *Custom) String() string {
	if s.userSuppliedName == "" {
		return "custom"
	}
	return s.userSuppliedName
}

// Query handles a resolving a given domain name to a list of IPs
func (s *Custom) Query(ctx context.Context, d doh.Domain, t doh.Type) (*doh.Response, error) {
	if s.Lock == nil {
		s.Lock = semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0)))
	}

	if err := s.Lock.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer s.Lock.Release(1)

	req, err := http.NewRequest("GET", s.userSuppliedBaseURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-json")

	req.Cancel = ctx.Done()
	req.WithContext(ctx)

	q := req.URL.Query()
	q.Add("name", d)
	q.Add("type", t)

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.Body == nil {
		return nil, errors.New("no resp body from server")
	}

	record := &doh.Response{}

	err = json.NewDecoder(resp.Body).Decode(record)
	if err != nil {
		return nil, err
	}

	return record, nil
}
