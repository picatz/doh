package safebrowsing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// A protobuf encoder for tests, the inverse of wire.go, so the fake
// server answers as the real API does.

func appendVarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

func appendTag(b []byte, num, wire int) []byte { return appendVarint(b, uint64(num)<<3|uint64(wire)) }

func appendBytesField(b []byte, num int, v []byte) []byte {
	b = appendTag(b, num, wireBytes)
	b = appendVarint(b, uint64(len(v)))
	return append(b, v...)
}

func appendVarintField(b []byte, num int, v uint64) []byte {
	return appendVarint(appendTag(b, num, wireVarint), v)
}

func encodeDuration(d time.Duration) []byte {
	var b []byte
	b = appendVarintField(b, 1, uint64(d/time.Second))
	if ns := d % time.Second; ns != 0 {
		b = appendVarintField(b, 2, uint64(ns))
	}
	return b
}

// bitWriter writes bits from the least significant end of each byte.
type bitWriter struct {
	data []byte
	n    int
}

func (w *bitWriter) bit(b uint64) {
	if w.n%8 == 0 {
		w.data = append(w.data, 0)
	}
	w.data[w.n/8] |= byte(b&1) << (w.n % 8)
	w.n++
}

// encodeRice Rice-codes sorted values with parameter k, or if k is zero,
// one suited to their spacing, as the server chooses it.
func encodeRice(values []uint32, k int) []byte {
	var b []byte
	if len(values) == 0 {
		return b
	}
	if k == 0 {
		k = 3
		if n := len(values); n > 1 {
			for avg := uint64(values[n-1]-values[0]) / uint64(n-1); k < 30 && 1<<(k+1) <= avg; k++ {
			}
		}
	}
	b = appendVarintField(b, 1, uint64(values[0]))
	b = appendVarintField(b, 2, uint64(k))
	if len(values) > 1 {
		b = appendVarintField(b, 3, uint64(len(values)-1))
		var w bitWriter
		for i := 1; i < len(values); i++ {
			d := uint64(values[i] - values[i-1])
			for range d >> k {
				w.bit(1)
			}
			w.bit(0)
			for j := range k {
				w.bit(d >> j)
			}
		}
		b = appendBytesField(b, 4, w.data)
	}
	return b
}

// fakeList is a list's state on the fake server, at a version.
type fakeList struct {
	prefixes []uint32
}

// fakeAPI is an in-memory Safe Browsing API: an http.RoundTripper, so
// tests need no network, and can run in a synctest bubble.
type fakeAPI struct {
	key string

	mu       sync.Mutex
	versions map[string][]fakeList // each list's versions, oldest first
	full     map[[32]byte][]byte   // full hash to its FullHash message
	minWait  time.Duration
	cache    time.Duration
	fail     bool
	badSum   bool
	requests []*http.Request
}

func newFakeAPI(key string) *fakeAPI {
	return &fakeAPI{key: key, versions: make(map[string][]fakeList), full: make(map[[32]byte][]byte), minWait: 30 * time.Minute, cache: 5 * time.Minute}
}

// publish adds a version of list with prefixes.
func (f *fakeAPI) publish(list string, prefixes ...uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := slices.Clone(prefixes)
	slices.Sort(p)
	p = slices.Compact(p)
	f.versions[list] = append(f.versions[list], fakeList{prefixes: p})
}

// listHost puts host on list, as the hash of "host/", with threat type t
// and attributes.
func (f *fakeAPI) listHost(list, host string, t ThreatType, attrs ...uint64) [32]byte {
	h := sha256.Sum256([]byte(host + "/"))
	var detail []byte
	detail = appendVarintField(detail, 1, uint64(t))
	for _, a := range attrs {
		detail = appendVarintField(detail, 2, a)
	}
	var msg []byte
	msg = appendBytesField(msg, 1, h[:])
	msg = appendBytesField(msg, 2, detail)

	f.mu.Lock()
	f.full[h] = msg
	var current []uint32
	if v := f.versions[list]; len(v) > 0 {
		current = v[len(v)-1].prefixes
	}
	f.mu.Unlock()
	f.publish(list, append(slices.Clone(current), prefixOf(h))...)
	return h
}

func (f *fakeAPI) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.URL.Path == path {
			n++
		}
	}
	return n
}

func (f *fakeAPI) last(path string) *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.requests) - 1; i >= 0; i-- {
		if f.requests[i].URL.Path == path {
			return f.requests[i]
		}
	}
	return nil
}

func (f *fakeAPI) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r)

	respond := func(status int, body []byte) (*http.Response, error) {
		return &http.Response{
			StatusCode: status, Status: http.StatusText(status), Request: r,
			Header: http.Header{"Content-Type": {"application/x-protobuf"}},
			Body:   io.NopCloser(strings.NewReader(string(body))),
		}, nil
	}
	if r.Header.Get("X-Goog-Api-Key") != f.key {
		return respond(http.StatusForbidden, nil)
	}
	if f.fail {
		return respond(http.StatusServiceUnavailable, nil)
	}

	q := r.URL.Query()
	switch r.URL.Path {
	case "/v5/hashLists:batchGet":
		names, versions := q["names"], q["version"]
		var out []byte
		for i, name := range names {
			all := f.versions[name]
			if len(all) == 0 {
				continue
			}
			have := -1
			if i < len(versions) && versions[i] != "" {
				v, err := base64.StdEncoding.DecodeString(versions[i])
				if err == nil && len(v) == 4 {
					have = int(binary.BigEndian.Uint32(v))
				}
			}
			out = appendBytesField(out, 1, f.hashList(name, all, have))
		}
		return respond(http.StatusOK, out)

	case "/v5/hashes:search":
		var out []byte
		for _, s := range q["hashPrefixes"] {
			p, err := base64.StdEncoding.DecodeString(s)
			if err != nil || len(p) != 4 {
				return respond(http.StatusBadRequest, nil)
			}
			for h, msg := range f.full {
				if string(h[:4]) == string(p) {
					out = appendBytesField(out, 1, msg)
				}
			}
		}
		out = appendBytesField(out, 2, encodeDuration(f.cache))
		return respond(http.StatusOK, out)
	}
	return respond(http.StatusNotFound, nil)
}

// hashList encodes the update from version have (or -1 for none) to the
// latest of all.
func (f *fakeAPI) hashList(name string, all []fakeList, have int) []byte {
	latest := all[len(all)-1]
	var msg []byte
	msg = appendBytesField(msg, 1, []byte(name))
	version := binary.BigEndian.AppendUint32(nil, uint32(len(all)-1))
	msg = appendBytesField(msg, 2, version)

	if have >= 0 && have < len(all) {
		msg = appendVarintField(msg, 3, 1) // partial
		old := all[have].prefixes
		var removals, additions []uint32
		for i, p := range old {
			if _, ok := slices.BinarySearch(latest.prefixes, p); !ok {
				removals = append(removals, uint32(i))
			}
		}
		for _, p := range latest.prefixes {
			if _, ok := slices.BinarySearch(old, p); !ok {
				additions = append(additions, p)
			}
		}
		if len(additions) > 0 {
			msg = appendBytesField(msg, 4, encodeRice(additions, 0))
		}
		if len(removals) > 0 {
			msg = appendBytesField(msg, 5, encodeRice(removals, 3))
		}
		if len(additions) == 0 && len(removals) == 0 {
			msg = appendBytesField(msg, 6, encodeDuration(f.minWait))
			return msg // unchanged: no checksum
		}
	} else if len(latest.prefixes) > 0 {
		msg = appendBytesField(msg, 4, encodeRice(latest.prefixes, 0))
	}
	msg = appendBytesField(msg, 6, encodeDuration(f.minWait))
	sum := (&prefixList{prefixes: latest.prefixes}).checksum()
	if f.badSum {
		sum[0] ^= 1
	}
	msg = appendBytesField(msg, 7, sum)
	return msg
}
