package filter

import (
	"math"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Tunneling heuristics. DNS tunnels (such as iodine and dnscat2) and
// exfiltration malware encode data in query names, so they send long,
// random-looking labels, often for NULL or TXT records, and many unique
// names under one domain in a short time.
const (
	// tunnelLabelLength flags any label this long, near the 63-byte limit
	// that encoders fill.
	tunnelLabelLength = 52

	// tunnelEntropyLength and tunnelEntropy flag shorter labels whose
	// characters are as varied as encoded data: base32 and base64 are
	// near 5 and 6 bits per character, while words and hex hashes are
	// below 4.
	tunnelEntropyLength = 30
	tunnelEntropy       = 4.2

	// tunnelBurst unique names under one registrable domain from one
	// client within tunnelPeriod flag that domain for that client for
	// tunnelCooldown.
	tunnelBurst    = 100
	tunnelPeriod   = time.Minute
	tunnelCooldown = 10 * time.Minute

	// tunnelMaxTracked bounds the number of client and domain pairs
	// tracked, so a flood of names can't exhaust memory.
	tunnelMaxTracked = 50_000
)

// entropy returns the Shannon entropy of s, in bits per byte.
func entropy(s string) float64 {
	var counts [256]int
	for i := range len(s) {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// encodedLabel reports whether any label of name, left of its registrable
// domain, looks like encoded data.
func encodedLabel(name, registrable string) (string, bool) {
	sub := strings.TrimSuffix(strings.TrimSuffix(name, registrable), ".")
	for label := range strings.SplitSeq(sub, ".") {
		switch {
		case len(label) >= tunnelLabelLength:
			return label, true
		case len(label) >= tunnelEntropyLength && entropy(label) >= tunnelEntropy:
			return label, true
		}
	}
	return "", false
}

// tunnelTracker counts unique names under each registrable domain, per
// client, to spot bursts.
type tunnelTracker struct {
	now func() time.Time

	mu      sync.Mutex
	windows map[tunnelKey]*tunnelWindow
	swept   time.Time
}

type tunnelKey struct {
	client netip.Addr
	domain string
}

type tunnelWindow struct {
	start   time.Time
	names   map[string]struct{}
	flagged time.Time // until when the domain is flagged, if after now
}

func newTunnelTracker() *tunnelTracker {
	return &tunnelTracker{now: time.Now, windows: make(map[tunnelKey]*tunnelWindow)}
}

// observe records a query for name under domain from client, and reports
// whether the pair is flagged as a tunnel.
func (t *tunnelTracker) observe(client netip.Addr, domain, name string) bool {
	now := t.now()
	k := tunnelKey{client, domain}

	t.mu.Lock()
	defer t.mu.Unlock()

	w, ok := t.windows[k]
	if !ok {
		t.sweep(now)
		if len(t.windows) >= tunnelMaxTracked {
			return false // fail open rather than grow without bound
		}
		w = &tunnelWindow{start: now, names: make(map[string]struct{})}
		t.windows[k] = w
	}

	if now.Before(w.flagged) {
		return true
	}
	if now.Sub(w.start) >= tunnelPeriod {
		w.start, w.names = now, make(map[string]struct{})
	}

	w.names[name] = struct{}{}
	if len(w.names) >= tunnelBurst {
		w.flagged = now.Add(tunnelCooldown)
		w.names = make(map[string]struct{})
		return true
	}
	return false
}

// sweep forgets windows that have expired and aren't flagged, at most
// once per window. t.mu must be held.
func (t *tunnelTracker) sweep(now time.Time) {
	if now.Sub(t.swept) < tunnelPeriod {
		return
	}
	t.swept = now
	for k, w := range t.windows {
		if now.Sub(w.start) >= tunnelPeriod && !now.Before(w.flagged) {
			delete(t.windows, k)
		}
	}
}

// isTunnelType reports whether qtype is one only tunnels ask for.
func isTunnelType(qtype uint16) bool {
	return qtype == dns.TypeNULL
}
