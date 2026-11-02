package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The test vector from the Standard Webhooks specification's reference
// libraries (https://github.com/standard-webhooks/standard-webhooks).
const (
	vectorSecret    = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	vectorID        = "msg_p5jXN8AQM9LWM0D4loKWxJek"
	vectorTimestamp = 1614265330
	vectorBody      = `{"test": 2432232314}`
	vectorSignature = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
)

func TestSign_StandardWebhooksVector(t *testing.T) {
	got, err := Sign(vectorSecret, vectorID, time.Unix(vectorTimestamp, 0), []byte(vectorBody))
	if err != nil || got != vectorSignature {
		t.Errorf("Sign = %q, %v, want %q", got, err, vectorSignature)
	}
}

func TestVerify(t *testing.T) {
	at := time.Unix(vectorTimestamp, 0)
	header := func(sig string, ts int64) http.Header {
		return http.Header{"Webhook-Id": {vectorID}, "Webhook-Timestamp": {strconv.FormatInt(ts, 10)}, "Webhook-Signature": {sig}}
	}
	other := newSecret()
	otherSig, _ := Sign(other, vectorID, at, []byte(vectorBody))

	for _, tt := range []struct {
		desc   string
		secret string
		header http.Header
		body   string
		now    time.Time
		ok     bool
	}{
		{"valid", vectorSecret, header(vectorSignature, vectorTimestamp), vectorBody, at, true},
		{"one of several", vectorSecret, header("v1,bm9wZQ== v2,abc "+vectorSignature, vectorTimestamp), vectorBody, at.Add(time.Minute), true},
		{"tampered body", vectorSecret, header(vectorSignature, vectorTimestamp), `{"test": 2432232315}`, at, false},
		{"wrong secret", other, header(vectorSignature, vectorTimestamp), vectorBody, at, false},
		{"another secret's signature", vectorSecret, header(otherSig, vectorTimestamp), vectorBody, at, false},
		{"replayed later", vectorSecret, header(vectorSignature, vectorTimestamp), vectorBody, at.Add(DefaultTolerance + time.Second), false},
		{"from the future", vectorSecret, header(vectorSignature, vectorTimestamp), vectorBody, at.Add(-DefaultTolerance - time.Second), false},
		{"timestamp changed", vectorSecret, header(vectorSignature, vectorTimestamp+1), vectorBody, at, false},
		{"unknown version", vectorSecret, header("v2,"+strings.TrimPrefix(vectorSignature, "v1,"), vectorTimestamp), vectorBody, at, false},
		{"no signature", vectorSecret, header("", vectorTimestamp), vectorBody, at, false},
		{"not a secret", "MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", header(vectorSignature, vectorTimestamp), vectorBody, at, false},
	} {
		err := Verify(tt.secret, tt.header, []byte(tt.body), tt.now, 0)
		if (err == nil) != tt.ok {
			t.Errorf("%s: Verify = %v, want ok %v", tt.desc, err, tt.ok)
		}
	}
}

// startPosting returns an engine, not started, whose deliveries really
// post, and that resolves names with hosts.
func startPosting(t *testing.T, hosts map[string][]netip.Addr) *Engine {
	t.Helper()
	e, err := newEngine(Options{LookupNetIP: func(_ context.Context, host string) ([]netip.Addr, error) {
		if addrs, ok := hosts[host]; ok {
			return addrs, nil
		}
		return nil, errors.New("no such host " + host)
	}})
	if err != nil {
		t.Fatal(err)
	}
	e.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	e.start()
	t.Cleanup(func() { e.Close() })
	return e
}

// waitDelivery waits for scope's newest delivery.
func waitDelivery(t *testing.T, e *Engine, scope string) Delivery {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, deliveries := e.Get(scope); len(deliveries) > 0 {
			return deliveries[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no delivery")
	return Delivery{}
}

func TestWebhook_SignedDelivery(t *testing.T) {
	type received struct {
		header http.Header
		body   []byte
	}
	got := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- received{r.Header.Clone(), body}
	}))
	defer srv.Close()

	e := startPosting(t, nil)
	d, secret, err := e.AddDestination(context.Background(), "", NewDestination{Type: Webhook, URL: srv.URL + "/hook", Name: "Home Assistant"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, SecretPrefix) || d.Type != Webhook || d.Name != "Home Assistant" {
		t.Fatalf("added %+v with secret %q", d, secret)
	}

	alert := e.stamp("", e.words.threat(new(threatEntry("", "kids", "kids-ipad", "evil.example"))))
	e.enqueue("", alert)
	r := <-got

	if err := Verify(secret, r.header, r.body, time.Now(), 0); err != nil {
		t.Errorf("the delivery doesn't verify: %v", err)
	}
	if r.header.Get(HeaderID) != alert.ID || r.header.Get("Content-Type") != "application/json" || r.header.Get("User-Agent") != userAgent {
		t.Errorf("headers = %v", r.header)
	}

	// The body follows the documented schema.
	var body map[string]any
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "type", "scope", "kind", "title", "body", "time", "details"} {
		if _, ok := body[key]; !ok {
			t.Errorf("body lacks %q: %s", key, r.body)
		}
	}
	if body["type"] != "alert.threat" || body["kind"] != "threat" || body["details"].(map[string]any)["name"] != "evil.example" {
		t.Errorf("body = %s", r.body)
	}
	if del := waitDelivery(t, e, ""); !del.OK || del.Attempts != 1 || del.Destination != d.ID || del.Summary != alert.Title {
		t.Errorf("delivery = %+v", del)
	}
}

func TestNtfy_Delivery(t *testing.T) {
	got := make(chan *http.Request, 1)
	bodies := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r
		bodies <- string(b)
	}))
	defer srv.Close()

	e := startPosting(t, nil)
	e.words.origin = "https://admin.dns.example"
	d, secret, err := e.AddDestination(context.Background(), "", NewDestination{Type: Ntfy, URL: srv.URL + "/family-alerts"})
	if err != nil || secret != "" {
		t.Fatalf("add = %+v, %q, %v", d, secret, err)
	}
	alert := e.stamp("", e.words.threat(new(threatEntry("", "kids", "kids-ipad", "evil.example"))))
	alert.Title = "Threat blocked on Zoë's iPad"
	e.enqueue("", alert)

	r, body := <-got, <-bodies
	if r.URL.Path != "/family-alerts" || r.URL.RawQuery != "" {
		t.Errorf("posted to %s: nothing may be added to the URL", r.URL)
	}
	title, err := new(mime.WordDecoder).DecodeHeader(r.Header.Get("Title"))
	if err != nil || title != alert.Title {
		t.Errorf("Title = %q (%q), %v", r.Header.Get("Title"), title, err)
	}
	if r.Header.Get("Tags") != "shield" || r.Header.Get("Priority") != "4" || r.Header.Get("Click") != alert.Details.Link || alert.Details.Link == "" {
		t.Errorf("headers = %v", r.Header)
	}
	if body != alert.Body || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("body = %q", body)
	}
}

func TestDelivery_RetriesAndRedirects(t *testing.T) {
	var calls, followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/flaky":
			if calls.Add(1) < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		case "/moved":
			http.Redirect(w, r, target.URL, http.StatusFound)
		case "/gone":
			calls.Add(1)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Run("retries until it works", func(t *testing.T) {
		e := startPosting(t, nil)
		addAt(t, e, srv.URL+"/flaky")
		e.enqueue("", e.stamp("", e.words.test(time.Now())))
		if del := waitDelivery(t, e, ""); !del.OK || del.Attempts != 3 {
			t.Errorf("delivery = %+v, want OK after 3 attempts", del)
		}
	})
	t.Run("never follows redirects", func(t *testing.T) {
		e := startPosting(t, nil)
		addAt(t, e, srv.URL+"/moved")
		e.enqueue("", e.stamp("", e.words.test(time.Now())))
		del := waitDelivery(t, e, "")
		if del.OK || del.Attempts != 1 || !strings.Contains(del.Error, "redirect") || followed.Load() != 0 {
			t.Errorf("delivery = %+v, followed %d times", del, followed.Load())
		}
		_, dests, _ := e.Get("")
		if dests[0].LastError == "" || dests[0].LastFailure.IsZero() {
			t.Errorf("failure not recorded: %+v", dests[0])
		}
	})
	t.Run("doesn't retry what retrying won't fix", func(t *testing.T) {
		calls.Store(0)
		e := startPosting(t, nil)
		addAt(t, e, srv.URL+"/gone")
		e.enqueue("", e.stamp("", e.words.test(time.Now())))
		if del := waitDelivery(t, e, ""); del.OK || del.Attempts != 1 || calls.Load() != 1 {
			t.Errorf("delivery = %+v after %d calls", del, calls.Load())
		}
	})
}

// addAt adds the operator's ntfy destination at url.
func addAt(t *testing.T, e *Engine, url string) {
	t.Helper()
	if _, _, err := e.AddDestination(context.Background(), "", NewDestination{Type: Ntfy, URL: url}); err != nil {
		t.Fatal(err)
	}
}

func TestDestinations_RefuseNonPublicForTenants(t *testing.T) {
	// Tenants' URLs that are obviously not public are refused when added.
	e := startPosting(t, nil)
	for _, u := range []string{
		"https://127.0.0.1/hook",
		"https://10.1.2.3/hook",
		"https://192.168.1.1/hook",
		"https://172.16.0.1/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://100.64.0.1/hook",
		"https://[::1]/hook",
		"https://[fd00::1]/hook",
		"https://[fe80::1]/hook",
		"https://[::ffff:127.0.0.1]/hook",
		"https://0.0.0.0/hook",
		"https://localhost/hook",
		"https://printer.localhost/hook",
		"https://intranet/hook",
		"http://ntfy.sh/topic",
		"ftp://ntfy.sh/topic",
		"https://ntfy.sh/topic#frag",
		"https://ntfy.sh",
		"ntfy.sh/topic",
	} {
		if _, _, err := e.AddDestination(context.Background(), "smiths", NewDestination{Type: Ntfy, URL: u}); !errors.Is(err, ErrInvalid) {
			t.Errorf("tenant added %s: %v", u, err)
		}
	}
	if _, _, err := e.AddDestination(context.Background(), "smiths", NewDestination{Type: Ntfy, URL: "https://ntfy.sh/smith-family"}); err != nil {
		t.Errorf("tenant can't add a public URL: %v", err)
	}

	// The operator may use http, but only to loopback.
	for u, ok := range map[string]bool{
		"http://127.0.0.1:8080/hook": true,
		"http://localhost:8080/hook": true,
		"http://[::1]:8080/hook":     true,
		"https://10.1.2.3/hook":      true,
		"http://10.1.2.3/hook":       false,
		"http://ntfy.sh/topic":       false,
	} {
		_, _, err := e.AddDestination(context.Background(), "", NewDestination{Type: Webhook, URL: u})
		if (err == nil) != ok {
			t.Errorf("operator adding %s: %v, want ok %v", u, err, ok)
		}
		if err == nil {
			_, dests, _ := e.Get("")
			_ = e.RemoveDestination("", dests[len(dests)-1].ID)
		}
	}
}

func TestDelivery_RefusesNonPublicAtDialTime(t *testing.T) {
	var reached atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer srv.Close()
	port := srv.Listener.Addr().(interface{ String() string }).String()
	port = port[strings.LastIndexByte(port, ':')+1:]

	e := startPosting(t, map[string][]netip.Addr{
		"internal.example": {netip.MustParseAddr("10.0.0.5")},
		"metadata.example": {netip.MustParseAddr("169.254.169.254")},
		"mixed.example":    {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("192.168.1.1")},
		"sneaky.example":   {netip.MustParseAddr("127.0.0.1")},
		"v6.example":       {netip.MustParseAddr("::1")},
	})

	// URLs as a tenant might have them once their names resolve
	// elsewhere, or as they'd be if checks when adding were bypassed.
	for _, u := range []string{
		"https://internal.example/hook",
		"https://metadata.example/latest",
		"https://mixed.example/hook",
		"https://sneaky.example:" + port + "/hook",
		"https://v6.example:" + port + "/hook",
		"https://127.0.0.1:" + port + "/hook",
	} {
		d := destination{Destination: Destination{ID: "x", Type: Ntfy}, url: u}
		err := e.post(t.Context(), "smiths", d, e.stamp("smiths", e.words.test(time.Now())))
		if !errors.Is(err, errRefused) || !isPermanent(err) {
			t.Errorf("tenant delivery to %s: %v, want refused", u, err)
		}
	}
	if reached.Load() != 0 {
		t.Errorf("a tenant's delivery reached a loopback server %d times", reached.Load())
	}

	// The operator's http deliveries reach only loopback.
	d := destination{Destination: Destination{ID: "x", Type: Ntfy}, url: "http://internal.example/hook"}
	if err := e.post(t.Context(), "", d, e.stamp("", e.words.test(time.Now()))); !errors.Is(err, errRefused) {
		t.Errorf("operator http delivery to a private address: %v, want refused", err)
	}
}

func TestAddrPolicy_Control(t *testing.T) {
	for _, tt := range []struct {
		p       addrPolicy
		address string
		ok      bool
	}{
		{publicOnly, "93.184.216.34:443", true},
		{publicOnly, "127.0.0.1:443", false},
		{publicOnly, "[::1]:443", false},
		{publicOnly, "10.0.0.5:443", false},
		{publicOnly, "169.254.169.254:80", false},
		{publicOnly, "[::ffff:192.168.1.1]:443", false},
		{publicOnly, "not-an-address:443", false},
		{loopbackOnly, "127.0.0.1:8080", true},
		{loopbackOnly, "[::1]:8080", true},
		{loopbackOnly, "10.0.0.5:8080", false},
		{anyAddr, "10.0.0.5:443", true},
	} {
		err := tt.p.control("tcp", tt.address, nil)
		if (err == nil) != tt.ok || err != nil && !errors.Is(err, errRefused) {
			t.Errorf("policy %d, control(%s) = %v, want ok %v", tt.p, tt.address, err, tt.ok)
		}
	}
}

func TestPublic(t *testing.T) {
	for s, want := range map[string]bool{
		"93.184.216.34":        true,
		"2606:4700:4700::1111": true,
		"127.0.0.1":            false,
		"10.0.0.1":             false,
		"172.31.255.255":       false,
		"192.168.0.1":          false,
		"169.254.169.254":      false,
		"100.100.100.100":      false,
		"0.0.0.0":              false,
		"255.255.255.255":      false,
		"224.0.0.1":            false,
		"198.18.0.1":           false,
		"::1":                  false,
		"::":                   false,
		"fd12::1":              false,
		"fe80::1":              false,
		"::ffff:10.0.0.1":      false,
		"64:ff9b::a00:1":       false,
		"2002:a00:1::":         false,
		"2001:db8::1":          false,
	} {
		if got := public(netip.MustParseAddr(s)); got != want {
			t.Errorf("public(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestDestinations_SecretShownOnce(t *testing.T) {
	e := startPosting(t, nil)
	d, secret, err := e.AddDestination(context.Background(), "", NewDestination{Type: Webhook, URL: "https://user:hunter2@hooks.example/doh?token=abc"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, SecretPrefix) {
		t.Fatalf("secret = %q", secret)
	}
	_, dests, _ := e.Get("")
	b, _ := json.Marshal(dests)
	db, _ := json.Marshal(d)
	for _, out := range []string{string(b), string(db)} {
		if strings.Contains(out, strings.TrimPrefix(secret, SecretPrefix)) || strings.Contains(out, "hunter2") {
			t.Errorf("a destination shows a secret: %s", out)
		}
	}
	if !strings.Contains(string(b), "user:xxxxx@hooks.example") {
		t.Errorf("destinations = %s", b)
	}
}

func TestStore_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.json")
	e, err := New(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	settings, err := e.SetSettings("smiths", Settings{Kinds: []Kind{KindNewDevice, KindThreat, KindThreat}, QuietHours: &QuietHours{Start: "22:00", End: "07:00"}, TimeZone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []Kind{KindThreat, KindNewDevice}; len(settings.Kinds) != 2 || settings.Kinds[0] != want[0] || settings.Kinds[1] != want[1] {
		t.Errorf("kinds kept as %q, want %q", settings.Kinds, want)
	}
	hook, secret, err := e.AddDestination(context.Background(), "smiths", NewDestination{Type: Webhook, URL: "https://hooks.example/doh", Name: "Hub", CreatedBy: "Ann"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.AddDestination(context.Background(), "", NewDestination{Type: Ntfy, URL: "https://ntfy.sh/ops"}); err != nil {
		t.Fatal(err)
	}
	e.store.seeDevice("smiths", "client:192.168.1.5", time.Now())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	if fi, err := os.Stat(path); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("alerts.json: %v, mode %v, want 0600", err, fi.Mode().Perm())
	}

	e, err = New(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	got, dests, _ := e.Get("smiths")
	if got.TimeZone != "UTC" || got.QuietHours == nil || got.QuietHours.Start != "22:00" || len(got.Kinds) != 2 {
		t.Errorf("settings after reopening = %+v", got)
	}
	if len(dests) != 1 || dests[0].ID != hook.ID || dests[0].Name != "Hub" || dests[0].CreatedBy != "Ann" {
		t.Errorf("destinations after reopening = %+v", dests)
	}
	if full := e.store.destinations("smiths"); full[0].secret != secret {
		t.Error("the webhook secret didn't survive reopening")
	}
	if isNew, _ := e.store.seeDevice("smiths", "client:192.168.1.5", time.Now()); isNew {
		t.Error("a seen device was forgotten")
	}
	if _, dests, _ := e.Get(""); len(dests) != 1 {
		t.Errorf("the operator's destinations after reopening = %+v", dests)
	}

	// Forgetting a tenant forgets everything about it.
	if err := e.ForgetScope("smiths"); err != nil {
		t.Fatal(err)
	}
	if _, dests, _ := e.Get("smiths"); len(dests) != 0 {
		t.Errorf("forgotten tenant still has %+v", dests)
	}
}

func TestStore_RejectsInvalidFiles(t *testing.T) {
	for name, content := range map[string]string{
		"not JSON":           `{`,
		"unknown version":    `{"version":2,"scopes":[]}`,
		"unknown field":      `{"version":1,"scopes":[],"extra":true}`,
		"duplicate scope":    `{"version":1,"scopes":[{"scope":"a"},{"scope":"a"}]}`,
		"bad kind":           `{"version":1,"scopes":[{"scope":"","settings":{"kinds":["everything"]}}]}`,
		"tenant list kind":   `{"version":1,"scopes":[{"scope":"a","settings":{"kinds":["list-failed"]}}]}`,
		"secretless hook":    `{"version":1,"scopes":[{"scope":"","destinations":[{"id":"x","type":"webhook","url":"https://h.example/","created":"2026-01-01T00:00:00Z"}]}]}`,
		"private for tenant": `{"version":1,"scopes":[{"scope":"a","destinations":[{"id":"x","type":"ntfy","url":"https://10.0.0.1/t","created":"2026-01-01T00:00:00Z"}]}]}`,
	} {
		path := filepath.Join(t.TempDir(), "alerts.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openStore(path); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

func TestStore_BoundsSeenDevices(t *testing.T) {
	s, _ := openStore("")
	start := time.Now()
	for i := range MaxSeenDevices + 10 {
		s.seeDevice("", "client:"+strconv.Itoa(i), start.Add(time.Duration(i)*time.Second))
	}
	if n := len(s.scopes[""].devices); n != MaxSeenDevices {
		t.Errorf("remembered %d devices, want %d", n, MaxSeenDevices)
	}
	if isNew, _ := s.seeDevice("", "client:0", start.Add(time.Hour)); !isNew {
		t.Error("the least recently seen device wasn't the one forgotten")
	}
}
