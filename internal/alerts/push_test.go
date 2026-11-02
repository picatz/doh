package alerts

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/picatz/doh/internal/webpush"
)

func TestKnownPushService(t *testing.T) {
	for _, host := range []string{
		"fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com",
		"api.push.apple.com", "api.sandbox.push.apple.com", "wns2-par02p.notify.windows.com", "db5.notify.windows.com",
		"FCM.googleapis.com",
	} {
		if !KnownPushService(host) {
			t.Errorf("%s isn't known", host)
		}
	}
	for _, host := range []string{
		"", "googleapis.com", "xfcm.googleapis.com", "fcm.googleapis.com.evil.example", "evil.example",
		"push.apple.com", ".push.apple.com", "evilpush.apple.com", "push.apple.com.evil.example", "a..push.apple.com",
		"notify.windows.com", "evilnotify.windows.com", "-x.notify.windows.com", "x_y.notify.windows.com",
		"updates.push.services.mozilla.com.evil.example", "push.services.mozilla.com", "127.0.0.1", "localhost",
		"fcm.googleapis.com.", "a b.push.apple.com",
	} {
		if KnownPushService(host) {
			t.Errorf("%q is known", host)
		}
	}
}

func TestCheckPushEndpoint(t *testing.T) {
	for _, ok := range []string{
		"https://fcm.googleapis.com/fcm/send/abc:def",
		"https://fcm.googleapis.com:443/fcm/send/abc",
		"https://updates.push.services.mozilla.com/wpush/v2/gAAAA",
		"https://web.push.apple.com/QGuQyavXutnMH",
		"https://wns2-par02p.notify.windows.com/w/?token=BQYAAA",
	} {
		u, _ := url.Parse(ok)
		if err := checkPushEndpoint(u); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://fcm.googleapis.com/fcm/send/abc",
		"https://fcm.googleapis.com:8443/fcm/send/abc",
		"https://user:pw@fcm.googleapis.com/fcm/send/abc",
		"https://fcm.googleapis.com/",
		"https://fcm.googleapis.com",
		"https://fcm.googleapis.com/x#frag",
		"https://FCM.googleapis.com/fcm/send/abc",
		"https://169.254.169.254/latest/meta-data",
		"https://ntfy.sh/topic",
		"https://fcm.googleapis.com.evil.example/fcm/send/abc",
	} {
		u, _ := url.Parse(bad)
		if err := checkPushEndpoint(u); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want invalid", bad, err)
		}
	}
}

// browser is a browser's side of a push subscription.
type browser struct {
	key  *ecdh.PrivateKey
	auth []byte
}

func newBrowser(t *testing.T) browser {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, webpush.AuthSize)
	_, _ = rand.Read(auth)
	return browser{k, auth}
}

func (b browser) subscription(endpoint string) *webpush.Subscription {
	return &webpush.Subscription{Endpoint: endpoint, Keys: webpush.SubscriptionKeys{
		P256DH: base64.RawURLEncoding.EncodeToString(b.key.PublicKey().Bytes()),
		Auth:   base64.RawURLEncoding.EncodeToString(b.auth),
	}}
}

func TestPush_AddDestination(t *testing.T) {
	e, err := newEngine(Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	b := newBrowser(t)
	endpoint := "https://fcm.googleapis.com/fcm/send/secret-token-of-this-browser"
	d, secret, err := e.AddDestination(ctx, "smiths", NewDestination{Type: Push, Subscription: b.subscription(endpoint), Name: "Alex's phone"})
	if err != nil {
		t.Fatal(err)
	}
	if d.State != Active || d.URL != "https://fcm.googleapis.com/…" || secret != "" || d.Subscription != SubscriptionID(endpoint) {
		t.Fatalf("added %+v", d)
	}
	// Nothing that would let anyone else push to it is shown.
	_, dests, _ := e.Get("smiths")
	j, _ := json.Marshal(dests)
	for _, hidden := range []string{"secret-token", b.subscription(endpoint).Keys.Auth, b.subscription(endpoint).Keys.P256DH} {
		if strings.Contains(string(j), hidden) {
			t.Errorf("%q shows: %s", hidden, j)
		}
	}

	// Subscribing again renews it, rather than adding another.
	again, _, err := e.AddDestination(ctx, "smiths", NewDestination{Type: Push, Subscription: newBrowser(t).subscription(endpoint)})
	if err != nil || again.ID != d.ID || again.Name != "Alex's phone" {
		t.Fatalf("again = %+v, %v", again, err)
	}
	if _, dests, _ := e.Get("smiths"); len(dests) != 1 {
		t.Errorf("%d destinations", len(dests))
	}

	sub := func(f func(*webpush.Subscription)) *webpush.Subscription {
		s := b.subscription(endpoint)
		f(s)
		return s
	}
	for desc, s := range map[string]*webpush.Subscription{
		"no subscription":  nil,
		"another service":  sub(func(s *webpush.Subscription) { s.Endpoint = "https://push.evil.example/x" }),
		"a private host":   sub(func(s *webpush.Subscription) { s.Endpoint = "https://10.0.0.1/x" }),
		"http":             sub(func(s *webpush.Subscription) { s.Endpoint = "http://fcm.googleapis.com/fcm/send/x" }),
		"a bad key":        sub(func(s *webpush.Subscription) { s.Keys.P256DH = "AAAA" }),
		"a short secret":   sub(func(s *webpush.Subscription) { s.Keys.Auth = "AAAA" }),
		"another port":     sub(func(s *webpush.Subscription) { s.Endpoint = "https://fcm.googleapis.com:444/x" }),
		"an endpoint only": {Endpoint: endpoint},
	} {
		if _, _, err := e.AddDestination(ctx, "smiths", NewDestination{Type: Push, Subscription: s}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want invalid", desc, err)
		}
	}
}

// fakePushService is a push service for tests: it checks each request's
// VAPID token, decrypts it as the browser would, and answers with codes
// it's given.
type fakePushService struct {
	t   *testing.T
	srv *httptest.Server
	b   browser
	key string // the VAPID key requests must be signed with

	mu       sync.Mutex
	codes    []int // the next responses' codes; 201 when empty
	headers  []http.Header
	received []pushMessage
	times    []time.Time
}

func newFakePushService(t *testing.T, key string) *fakePushService {
	p := &fakePushService{t: t, b: newBrowser(t), key: key}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(p.handle))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakePushService) handle(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.headers = append(p.headers, r.Header.Clone())
	p.times = append(p.times, time.Now())
	code := http.StatusCreated
	if len(p.codes) > 0 {
		code, p.codes = p.codes[0], p.codes[1:]
	}
	if code == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	pub, err := webpush.VerifyAuthorization(r.Header.Get("Authorization"), "https://"+r.Host+r.URL.Path, time.Now())
	if err != nil || base64.RawURLEncoding.EncodeToString(pub) != p.key {
		p.t.Errorf("VAPID: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	body, _ := io.ReadAll(r.Body)
	plain, err := webpush.Decrypt(body, p.b.key, p.b.auth)
	if err != nil {
		p.t.Errorf("decrypting: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var m pushMessage
	if err := json.Unmarshal(plain, &m); err != nil {
		p.t.Errorf("payload %q: %v", plain, err)
	}
	if code < 300 {
		p.received = append(p.received, m)
	}
	w.WriteHeader(code)
}

// client returns an HTTP client that reaches the fake service for any
// host, as if it were the push service the endpoint names.
func (p *fakePushService) client() *http.Client {
	tr := p.srv.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = "example.com" // in httptest's certificate
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, p.srv.Listener.Addr().String())
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// pushEngine returns an engine whose operator deliveries go to a fake push
// service.
func pushEngine(t *testing.T, opts Options) (*Engine, *fakePushService) {
	t.Helper()
	e, err := newEngine(opts)
	if err != nil {
		t.Fatal(err)
	}
	key, err := e.PushKey()
	if err != nil {
		t.Fatal(err)
	}
	p := newFakePushService(t, key)
	e.operatorClient = p.client()
	e.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	e.start()
	t.Cleanup(func() { e.Close() })
	return e, p
}

func TestPush_Delivery(t *testing.T) {
	e, p := pushEngine(t, Options{Origin: "https://admin.dns.example.com", PushSubject: "mailto:ops@dns.example.com"})
	endpoint := "https://fcm.googleapis.com/fcm/send/abc"
	d, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Push, Subscription: p.b.subscription(endpoint)})
	if err != nil {
		t.Fatal(err)
	}

	alert := e.stamp("", e.words.threat(new(threatEntry("", "kids", "kids-ipad", "evil.example"))))
	e.enqueue("", alert)
	if del := waitDelivery(t, e, ""); !del.OK || del.Destination != d.ID {
		t.Fatalf("delivery = %+v", del)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	h, m := p.headers[0], p.received[0]
	for k, want := range map[string]string{
		"Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream",
		"Urgency": "high", "Ttl": "86400", "Topic": pushTopic(m.Tag),
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if len(h.Get("Topic")) != 32 {
		t.Errorf("Topic %q isn't 32 characters", h.Get("Topic"))
	}
	if m.ID != alert.ID || m.Kind != KindThreat || m.Title != "Threat blocked on kids-ipad" || m.URL != alert.Details.Link || m.Tag != "doh:threat:kids/kids-ipad" {
		t.Errorf("message = %+v", m)
	}
	if strings.Contains(m.Body, "https://") || !strings.HasSuffix(m.Body, "Nothing reached it.") {
		t.Errorf("body = %q", m.Body)
	}
}

func TestPush_GoneSubscriptions(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusGone} {
		e, p := pushEngine(t, Options{})
		d, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Push, Subscription: p.b.subscription("https://fcm.googleapis.com/fcm/send/abc")})
		if err != nil {
			t.Fatal(err)
		}
		p.codes = []int{code}
		if res, err := e.Test(t.Context(), ""); err != nil || res[0].OK {
			t.Fatalf("%d: Test = %+v, %v", code, res, err)
		}
		_, dests, _ := e.Get("")
		if dests[0].State != Gone {
			t.Errorf("%d: state = %s, want gone", code, dests[0].State)
		}
		if _, err := e.Test(t.Context(), ""); !errors.Is(err, ErrNoDestinations) {
			t.Errorf("%d: a gone subscription is still sent to: %v", code, err)
		}

		// Subscribing again brings it back.
		again, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Push, Subscription: p.b.subscription("https://fcm.googleapis.com/fcm/send/abc")})
		if err != nil || again.ID != d.ID || again.State != Active {
			t.Errorf("%d: again = %+v, %v", code, again, err)
		}
	}
}

func TestPush_RetryAfter(t *testing.T) {
	e, p := pushEngine(t, Options{})
	if _, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Push, Subscription: p.b.subscription("https://fcm.googleapis.com/fcm/send/abc")}); err != nil {
		t.Fatal(err)
	}
	p.codes = []int{http.StatusTooManyRequests}
	e.enqueue("", e.stamp("", e.words.test(time.Now())))
	del := waitDelivery(t, e, "")
	if !del.OK || del.Attempts != 2 {
		t.Fatalf("delivery = %+v", del)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if wait := p.times[1].Sub(p.times[0]); wait < time.Second {
		t.Errorf("retried after %s; Retry-After asked for 1s", wait)
	}
}

// TestPush_EndpointCheckedWhenSent checks that an endpoint off the list
// is refused when sending too, whatever the store holds.
func TestPush_EndpointCheckedWhenSent(t *testing.T) {
	e, p := pushEngine(t, Options{})
	sub := p.b.subscription("https://push.evil.example/x")
	d := destination{Destination: Destination{ID: "x", Type: Push, State: Active}, url: sub.Endpoint, p256dh: sub.Keys.P256DH, auth: sub.Keys.Auth}
	if err := e.post(t.Context(), "", d, e.stamp("", e.words.test(time.Now()))); !errors.Is(err, ErrInvalid) || !isPermanent(err) {
		t.Fatalf("post = %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.headers) > 0 {
		t.Error("the request was sent")
	}
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for h, want := range map[string]time.Duration{
		"": 0, "3": 3 * time.Second, "-1": 0, "soon": 0, "999999999": 24 * time.Hour,
		"Mon, 02 Nov 2026 12:01:00 GMT": time.Minute, "Mon, 02 Nov 2026 11:00:00 GMT": 0,
	} {
		if got := retryAfter(h, now); got != want {
			t.Errorf("retryAfter(%q) = %s, want %s", h, got, want)
		}
	}
}

// TestPush_TenantsReachOnlyPublicAddresses checks that a tenant's push
// endpoint, even on a known push service, goes through the dial guard:
// a name made to resolve to a private address isn't connected to.
func TestPush_TenantsReachOnlyPublicAddresses(t *testing.T) {
	e := startPosting(t, map[string][]netip.Addr{"fcm.googleapis.com": {netip.MustParseAddr("10.0.0.7")}})
	if _, _, err := e.AddDestination(t.Context(), "smiths", NewDestination{Type: Push, Subscription: newBrowser(t).subscription("https://fcm.googleapis.com/fcm/send/abc")}); err != nil {
		t.Fatal(err)
	}
	res, err := e.Test(t.Context(), "smiths")
	if err != nil || res[0].OK || !strings.Contains(res[0].Error, "isn't an address alerts may be sent to") {
		t.Fatalf("Test = %+v, %v", res, err)
	}
}

func TestPush_KeyKeptPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vapid.pem")
	e1, err := newEngine(Options{PushKeyPath: path})
	if err != nil {
		t.Fatal(err)
	}
	k1, err := e1.PushKey()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v, %v", info, err)
	}
	e2, _ := newEngine(Options{PushKeyPath: path})
	if k2, err := e2.PushKey(); err != nil || k2 != k1 {
		t.Errorf("another engine's key = %q, %v; want %q", k2, err, k1)
	}
	if raw, _ := base64.RawURLEncoding.DecodeString(k1); len(raw) != webpush.PublicKeySize {
		t.Errorf("key = %q", k1)
	}
	if _, err := newEngine(Options{PushSubject: "ops@example.com"}); err == nil {
		t.Error("a push subject that isn't a URL was accepted")
	}
}

func TestPushPayload(t *testing.T) {
	a := Alert{ID: "msg_1", Kind: KindNewDevice, Title: "New device: tv",
		Body:    "tv started using doh. If you don't recognize it, see what it's been looking up: https://a.example/#/logs",
		Details: Details{Profile: "home", Client: "192.168.1.50", Link: "https://a.example/#/logs"}}
	b, err := pushPayload(a)
	if err != nil {
		t.Fatal(err)
	}
	var m pushMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Body != "tv started using doh. If you don't recognize it, see what it's been looking up." || m.Tag != "doh:new-device:home/192.168.1.50" {
		t.Errorf("message = %+v", m)
	}

	// However long the alert, it fits one record.
	a.Body = strings.Repeat("é", 10_000)
	a.Title = strings.Repeat("t", 10_000)
	a.Details.Link = "https://a.example/" + strings.Repeat("x", 3000)
	b, err = pushPayload(a)
	if err != nil || len(b) > webpush.MaxPlaintext {
		t.Fatalf("payload of %d bytes, %v", len(b), err)
	}
}

func TestStore_RoundTripsEmailAndPush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.json")
	s, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	b := newBrowser(t)
	sub := b.subscription("https://web.push.apple.com/abc")
	if _, err := s.upsertPush("", &destination{Destination: Destination{ID: "p1", Type: Push, State: Active}, url: sub.Endpoint, p256dh: sub.Keys.P256DH, auth: sub.Keys.Auth}); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := s.addDestination("", &destination{Destination: Destination{ID: "e1", Type: Email, State: Pending}, url: "mailto:alex@example.com", confirm: &confirmation{hash: hashCode("ABCDEFGHJK"), expires: expires}}); err != nil {
		t.Fatal(err)
	}
	if err := s.addDestination("", &destination{Destination: Destination{ID: "e2", Type: Email, State: Active}, url: "mailto:sam@example.com", unsubscribe: "tok"}); err != nil {
		t.Fatal(err)
	}
	s.markGone("", "p1")
	if err := s.flush(); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "ABCDEFGHJK") {
		t.Error("the file holds a confirmation code, not its hash")
	}

	s2, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, dests, _ := s2.view("")
	if len(dests) != 3 || dests[0].State != Gone || dests[1].State != Pending || !dests[1].ConfirmBy.Equal(expires) || dests[2].State != Active {
		t.Fatalf("reloaded %+v", dests)
	}
	if got := s2.destinations(""); len(got) != 1 || got[0].ID != "e2" || got[0].unsubscribe != "tok" {
		t.Errorf("deliverable = %+v", got)
	}
	// A hash must match in full; an empty token matches nothing.
	near := hashCode("ABCDEFGHJK")
	near = near[:len(near)-1] + string("01"[(near[len(near)-1]-'0'+1)%2])
	if _, _, err := s2.confirm(func(string) bool { return true }, near, time.Now(), "tok2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a hash differing in its last digit = %v", err)
	}
	if _, _, err := s2.unsubscribe(""); !errors.Is(err, ErrNotFound) {
		t.Errorf("an empty unsubscribe token = %v", err)
	}
	if _, d, err := s2.confirm(func(string) bool { return true }, hashCode("ABCDEFGHJK"), time.Now(), "tok2"); err != nil || d.ID != "e1" {
		t.Errorf("confirming after a reload = %+v, %v", d, err)
	}
}

func TestStore_RejectsInvalidEmailAndPush(t *testing.T) {
	keys := newBrowser(t).subscription("https://fcm.googleapis.com/x").Keys
	for desc, dest := range map[string]string{
		"push off the list":       `{"id":"a","type":"push","url":"https://evil.example/x","created":"2026-01-01T00:00:00Z","p256dh":"` + keys.P256DH + `","auth":"` + keys.Auth + `"}`,
		"push without keys":       `{"id":"a","type":"push","url":"https://fcm.googleapis.com/x","created":"2026-01-01T00:00:00Z"}`,
		"push with a bad key":     `{"id":"a","type":"push","url":"https://fcm.googleapis.com/x","created":"2026-01-01T00:00:00Z","p256dh":"AAAA","auth":"` + keys.Auth + `"}`,
		"email that isn't mailto": `{"id":"a","type":"email","url":"https://example.com","created":"2026-01-01T00:00:00Z"}`,
		"pending without a hash":  `{"id":"a","type":"email","url":"mailto:a@example.com","created":"2026-01-01T00:00:00Z","state":"pending"}`,
		"a hash, not pending":     `{"id":"a","type":"email","url":"mailto:a@example.com","created":"2026-01-01T00:00:00Z","confirm_hash":"ab"}`,
		"a pending webhook":       `{"id":"a","type":"webhook","url":"https://example.com/x","secret":"whsec_AAAA","created":"2026-01-01T00:00:00Z","state":"pending","confirm_hash":"ab"}`,
		"a gone email":            `{"id":"a","type":"email","url":"mailto:a@example.com","created":"2026-01-01T00:00:00Z","state":"gone"}`,
		"an unknown state":        `{"id":"a","type":"email","url":"mailto:a@example.com","created":"2026-01-01T00:00:00Z","state":"paused"}`,
		"pending, unsubscribable": `{"id":"a","type":"email","url":"mailto:a@example.com","created":"2026-01-01T00:00:00Z","state":"pending","confirm_hash":"ab","unsubscribe":"t"}`,
	} {
		path := filepath.Join(t.TempDir(), "alerts.json")
		_ = os.WriteFile(path, []byte(`{"version":1,"scopes":[{"scope":"","destinations":[`+dest+`]}]}`), 0o600)
		if _, err := openStore(path); err == nil {
			t.Errorf("%s: loaded", desc)
		}
	}
}
