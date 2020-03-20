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

// Quad9 is a DNS over HTTPs resolver.
type Quad9 struct {
	Lock *semaphore.Weighted
}

// String is a custom printer for debugging purposes.
func (s *Quad9) String() string {
	return "quad9"
}

var quad9Base = "https://dns.quad9.net:5053/dns-query"

// Query handles a resolving a given domain name to a list of IPs
func (s *Quad9) Query(ctx context.Context, d doh.Domain, t doh.Type) (*doh.Response, error) {
	if s.Lock == nil {
		s.Lock = semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0)))
	}

	if err := s.Lock.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer s.Lock.Release(1)

	req, err := http.NewRequest("GET", quad9Base, nil)
	if err != nil {
		return nil, err
	}

	req.Cancel = ctx.Done()
	req.WithContext(ctx)

	q := req.URL.Query()
	q.Add("name", d)
	q.Add("type", t)

	req.URL.RawQuery = q.Encode()

	resp, err := doh.Client.Do(req)
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
