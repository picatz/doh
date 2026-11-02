package alerts

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// FuzzCheckURL checks destination URLs as tenants and the operator give
// them: it must never panic; a tenant's accepted URL must be https to a
// public address or a dotted name; and only the operator may use http,
// and only to a loopback address.
func FuzzCheckURL(f *testing.F) {
	for _, s := range []string{
		"https://ntfy.sh/topic", "https://hooks.example.com/x?y=1", "http://127.0.0.1:8080/hook",
		"https://[::ffff:127.0.0.1]/x", "https://10.0.0.1/x", "https://169.254.169.254/latest", "https://localhost/x",
		"https://intranet/x", "https://user:pass@example.com/x", "https://example.com:0/x", "https://example.com/#frag",
		"https://[fe80::1%25eth0]/x", "https://0x7f000001/x", "https://2130706433/x", "https://100.64.0.1/x", "mailto:a@b",
	} {
		f.Add("", s, true)
		f.Add("tenant", s, false)
	}
	f.Fuzz(func(t *testing.T, scope, raw string, ntfy bool) {
		typ := Webhook
		if ntfy {
			typ = Ntfy
		}
		u, err := checkURL(scope, typ, raw)
		if err != nil {
			return
		}
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		addr, isAddr := netip.ParseAddr(host)
		switch u.Scheme {
		case "https":
		case "http":
			if scope != "" || !(host == "localhost" || strings.HasSuffix(host, ".localhost") || isAddr == nil && addr.Unmap().IsLoopback()) {
				t.Fatalf("http accepted for scope %q: %s", scope, raw)
			}
		default:
			t.Fatalf("scheme %q accepted: %s", u.Scheme, raw)
		}
		if scope == "" {
			return
		}
		if isAddr == nil {
			a := addr.Unmap()
			if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || !a.IsGlobalUnicast() {
				t.Fatalf("a tenant's URL to %v accepted: %s", a, raw)
			}
		} else if !strings.Contains(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") {
			t.Fatalf("a tenant's URL to %q accepted: %s", host, raw)
		}
	})
}

// FuzzVerify checks webhook signatures as a receiver would: it must never
// panic, and only a signature made with the secret, for that ID,
// timestamp, and body, verifies.
func FuzzVerify(f *testing.F) {
	secret := newSecret()
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"type":"threat"}`)
	sig, err := Sign(secret, "msg_1", now, body)
	if err != nil {
		f.Fatal(err)
	}
	ts := "1800000000"
	f.Add("msg_1", ts, sig, body)
	f.Add("msg_1", ts, "v1,AAAA "+sig, body)
	f.Add("msg_2", ts, sig, body)
	f.Add("msg_1", "99999999999999999999", sig, body)
	f.Add("msg_1", "-1", "v2,"+strings.TrimPrefix(sig, "v1,"), body)
	f.Fuzz(func(t *testing.T, id, timestamp, signature string, b []byte) {
		h := http.Header{}
		h.Set(HeaderID, id)
		h.Set(HeaderTimestamp, timestamp)
		h.Set(HeaderSignature, signature)
		if err := Verify(secret, h, b, now, 0); err != nil {
			return
		}
		// What verified must be what was signed: the same ID, a timestamp
		// for the same second, and the same body.
		if h.Get(HeaderID) != "msg_1" || h.Get(HeaderTimestamp) != ts || string(b) != string(body) {
			t.Fatalf("verified id %q, timestamp %q, body %q", h.Get(HeaderID), h.Get(HeaderTimestamp), b)
		}
	})
}

// FuzzSettingsNormalize checks alert settings as tenants send them:
// normalizing must never panic, and normalized settings are normalized.
func FuzzSettingsNormalize(f *testing.F) {
	f.Add("", "threat,new-device", "22:00", "07:00", "America/New_York")
	f.Add("tenant", "list-failed", "", "", "")
	f.Add("tenant", "threat,threat,bogus", "22:00", "22:00", "Local")
	f.Add("", "", "24:00", "7", "../../etc/passwd")
	f.Fuzz(func(t *testing.T, scope, kinds, start, end, tz string) {
		s := Settings{TimeZone: tz}
		for k := range strings.SplitSeq(kinds, ",") {
			s.Kinds = append(s.Kinds, Kind(k))
		}
		if start != "" || end != "" {
			s.QuietHours = &QuietHours{Start: start, End: end}
		}
		n, err := s.normalize(scope)
		if err != nil {
			return
		}
		again, err := n.normalize(scope)
		if err != nil || strings.Join(kindStrings(again.Kinds), ",") != strings.Join(kindStrings(n.Kinds), ",") {
			t.Fatalf("normalize isn't idempotent: %+v, then %+v, %v", n, again, err)
		}
		_ = n.Quiet(time.Unix(1_800_000_000, 0))
	})
}

func kindStrings(ks []Kind) []string {
	var out []string
	for _, k := range ks {
		out = append(out, string(k))
	}
	return out
}
