package alerts

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/mail"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct horse battery staple"

// parsed is a received email, decoded.
type parsed struct {
	header      mail.Header
	subject     string
	text, html  string
	rawHeaders  string
	unsubscribe string
}

func parseEmail(t *testing.T, data string) parsed {
	t.Helper()
	if strings.Contains(strings.ReplaceAll(data, "\r\n", ""), "\n") {
		t.Error("the message has a bare LF")
	}
	m, err := mail.ReadMessage(strings.NewReader(data))
	if err != nil {
		t.Fatalf("not an RFC 5322 message: %v\n%s", err, data)
	}
	p := parsed{header: m.Header, rawHeaders: data[:strings.Index(data, "\r\n\r\n")]}
	if p.subject, err = new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject")); err != nil {
		t.Fatalf("Subject %q: %v", m.Header.Get("Subject"), err)
	}
	p.unsubscribe = strings.Trim(m.Header.Get("List-Unsubscribe"), "<>")

	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("Content-Type = %q", m.Header.Get("Content-Type"))
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	for {
		part, err := mr.NextPart() // decodes quoted-printable
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(part)
		switch ct := part.Header.Get("Content-Type"); ct {
		case "text/plain; charset=utf-8":
			p.text = string(b)
		case "text/html; charset=utf-8":
			p.html = string(b)
		default:
			t.Errorf("unexpected part %q", ct)
		}
	}
	if p.text == "" || p.html == "" {
		t.Fatalf("missing a part: text %q, html %q", p.text, p.html)
	}
	return p
}

// mailEngine starts an engine that mails through srv at rawURL, with
// origin, logging to log.
func mailEngine(t *testing.T, srv *fakeSMTP, rawURL, origin string, log *bytes.Buffer) *Engine {
	t.Helper()
	cfg := srv.config(rawURL)
	opts := Options{Mail: &cfg, Origin: origin}
	if log != nil {
		opts.Logger = slog.New(slog.NewTextHandler(log, nil))
	}
	e, err := newEngine(opts)
	if err != nil {
		t.Fatal(err)
	}
	e.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	e.start()
	t.Cleanup(func() { e.Close() })
	return e
}

var codeRE = regexp.MustCompile(`\b[0-9A-Z]{5}-[0-9A-Z]{5}\b`)

// codeIn returns the confirmation code in an email.
func codeIn(t *testing.T, p parsed) string {
	t.Helper()
	code := codeRE.FindString(p.text)
	if code == "" || !strings.Contains(p.html, code) {
		t.Fatalf("no code in the confirmation email:\n%s", p.text)
	}
	return code
}

func TestSecret_NeverShown(t *testing.T) {
	s := Secret(testPassword)
	cfg := MailConfig{URL: "smtp://alerts@mail.example.com", Password: s, From: "alerts@example.com"}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("x", "password", s, "config", cfg)
	j, _ := json.Marshal(cfg)
	for _, out := range []string{
		fmt.Sprint(s), fmt.Sprintf("%s %q %v %+v %#v %x %d", s, s, s, s, s, s, s),
		fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), log.String(), string(j),
	} {
		if strings.Contains(out, testPassword) || strings.Contains(out, "636f7272") {
			t.Errorf("the password shows: %s", out)
		}
	}
	if s.Reveal() != testPassword {
		t.Error("Reveal doesn't give the secret")
	}
}

func TestCheckMailConfig(t *testing.T) {
	ok := MailConfig{URL: "smtp://alerts@mail.example.com", Password: "pw", From: "doh <alerts@example.com>"}
	if err := CheckMailConfig(ok); err != nil {
		t.Fatal(err)
	}
	for desc, c := range map[string]MailConfig{
		"password in the URL": {URL: "smtp://alerts:" + testPassword + "@mail.example.com", From: "alerts@example.com"},
		"another scheme":      {URL: "http://mail.example.com", From: "alerts@example.com"},
		"no host":             {URL: "smtp://", From: "alerts@example.com"},
		"a path":              {URL: "smtp://mail.example.com/x", From: "alerts@example.com"},
		"a bad port":          {URL: "smtp://mail.example.com:99999", From: "alerts@example.com"},
		"a user, no password": {URL: "smtp://alerts@mail.example.com", From: "alerts@example.com"},
		"a password, no user": {URL: "smtp://mail.example.com", Password: testPassword, From: "alerts@example.com"},
		"no sender":           {URL: "smtp://mail.example.com"},
		"a bad sender":        {URL: "smtp://mail.example.com", From: "not an address"},
	} {
		err := CheckMailConfig(c)
		if err == nil {
			t.Errorf("%s: accepted", desc)
		} else if strings.Contains(err.Error(), testPassword) {
			t.Errorf("%s: the error shows the password: %v", desc, err)
		}
	}
}

func TestParseAddress(t *testing.T) {
	for in, want := range map[string]string{
		"alex@example.com":         "alex@example.com",
		" mailto:Alex@Example.COM": "Alex@example.com",
		"a.b+alerts@mail.example":  "a.b+alerts@mail.example",
	} {
		if got, err := parseAddress(in); err != nil || got != want {
			t.Errorf("parseAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "alex", "alex@localhost", "Alex <alex@example.com>", "alex@example.com, eve@example.com",
		"alex@[127.0.0.1]", "alex@example.com\r\nBcc: eve@example.com", "ålex@example.com", strings.Repeat("a", 250) + "@example.com",
	} {
		if got, err := parseAddress(bad); err == nil {
			t.Errorf("parseAddress(%q) = %q, want an error", bad, got)
		}
	}
}

// TestMail_RequiresSTARTTLS checks that doh won't speak to a mail server
// that's not on this machine without TLS, and so never sends it the
// password or a message in the clear.
func TestMail_RequiresSTARTTLS(t *testing.T) {
	srv := newFakeSMTP(t, "mail.example.com")
	srv.mu.Lock()
	srv.startTLS, srv.user, srv.pass = false, "alerts", testPassword
	srv.mu.Unlock()
	m, err := newMailer(srv.config("smtp://alerts@mail.example.com:587"))
	if err != nil {
		t.Fatal(err)
	}
	err = m.send(t.Context(), "alex@example.com", []byte("Subject: x\r\n\r\nx\r\n"))
	if err == nil || !isPermanent(err) || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("send = %v, want a permanent STARTTLS error", err)
	}
	srv.mu.Lock()
	sawAuth := srv.sawAuth
	srv.mu.Unlock()
	if len(sawAuth) > 0 || len(srv.taken()) > 0 {
		t.Errorf("sent the password or a message in the clear: %q", sawAuth)
	}
}

func TestMail_VerifiesTLS(t *testing.T) {
	srv := newFakeSMTP(t, "other.example.com") // a certificate for another name
	cfg := srv.config("smtp://mail.example.com")
	m, _ := newMailer(cfg)
	if err := m.send(t.Context(), "alex@example.com", []byte("x\r\n")); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("send to a server with another's certificate = %v", err)
	}

	srv = newFakeSMTP(t, "mail.example.com")
	cfg = srv.config("smtp://mail.example.com")
	cfg.TLS = nil // the system's roots, which don't have the test CA
	m, _ = newMailer(cfg)
	if err := m.send(t.Context(), "alex@example.com", []byte("x\r\n")); err == nil {
		t.Fatal("sent to a server with an untrusted certificate")
	}
	if len(srv.taken()) > 0 {
		t.Error("a message was taken")
	}
}

// TestMail_LoopbackWithoutTLS checks the one exception: a mail server on
// this machine, such as a local relay, may be spoken to in the clear.
func TestMail_LoopbackWithoutTLS(t *testing.T) {
	srv := newFakeSMTP(t, "127.0.0.1")
	srv.mu.Lock()
	srv.startTLS = false
	srv.mu.Unlock()
	m, err := newMailer(srv.config("smtp://127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.send(t.Context(), "alex@example.com", []byte("Subject: x\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}
	if got := srv.taken(); len(got) != 1 || got[0].tls {
		t.Fatalf("taken %+v", got)
	}
}

func TestMail_Auth(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("implicit TLS %v", implicit), func(t *testing.T) {
			srv := newFakeSMTP(t, "mail.example.com")
			srv.mu.Lock()
			srv.implicitTLS, srv.startTLS, srv.user, srv.pass = implicit, !implicit, "alerts", testPassword
			srv.mu.Unlock()
			scheme := "smtp"
			if implicit {
				scheme = "smtps"
			}
			m, err := newMailer(srv.config(scheme + "://alerts@mail.example.com"))
			if err != nil {
				t.Fatal(err)
			}
			if err := m.send(t.Context(), "alex@example.com", []byte("Subject: x\r\n\r\nx\r\n")); err != nil {
				t.Fatal(err)
			}
			got := srv.taken()
			if len(got) != 1 || !got[0].tls || got[0].from != "alerts@dns.example.com" || got[0].to != "alex@example.com" {
				t.Fatalf("taken %+v", got)
			}
			srv.mu.Lock()
			sawPlain := srv.sawPlain
			srv.mu.Unlock()
			for _, verb := range sawPlain {
				if verb == "AUTH" || verb == "MAIL" {
					t.Errorf("%s was sent before TLS", verb)
				}
			}

			// The wrong password is refused, and the error, and the log,
			// never show the password.
			cfg := srv.config(scheme + "://alerts@mail.example.com")
			cfg.Password = "wrong " + testPassword
			m, _ = newMailer(cfg)
			err = m.send(t.Context(), "alex@example.com", []byte("x\r\n"))
			if err == nil || !isPermanent(err) || strings.Contains(err.Error(), testPassword) {
				t.Fatalf("wrong password: %v", err)
			}
		})
	}
}

func TestMail_TransientAndPermanentReplies(t *testing.T) {
	srv := newFakeSMTP(t, "mail.example.com")
	m, _ := newMailer(srv.config("smtp://mail.example.com"))
	srv.mu.Lock()
	srv.rcptReply = "450 mailbox busy"
	srv.mu.Unlock()
	if err := m.send(t.Context(), "alex@example.com", []byte("x\r\n")); err == nil || isPermanent(err) {
		t.Errorf("450: %v, want a retryable error", err)
	}
	srv.mu.Lock()
	srv.rcptReply = "550 no such user"
	srv.mu.Unlock()
	if err := m.send(t.Context(), "alex@example.com", []byte("x\r\n")); err == nil || !isPermanent(err) {
		t.Errorf("550: %v, want a permanent error", err)
	}
}

// TestEmail_Message checks an alert email as mail clients will read it:
// an RFC 5322 message with folded, encoded headers for a title that
// isn't ASCII, both parts, nothing remote, everything escaped, and a
// one-click unsubscribe link.
func TestEmail_Message(t *testing.T) {
	e, err := newEngine(Options{Origin: "https://admin.dns.example.com", Mail: &MailConfig{URL: "smtp://mail.example.com", From: "Família doh <alerts@dns.example.com>"}})
	if err != nil {
		t.Fatal(err)
	}
	title := `Bedrohung blockiert auf Kinder-iPad — 子供のタブレット <script>alert(1)</script> & "Ünïcödé" ` + strings.Repeat("ø", 40)
	a := Alert{ID: "msg_1", Kind: KindThreat, Title: title, Time: time.Now(),
		Body:    "doh blocked evil.example\r\nBcc: eve@example.com, for <b>Kids</b>. See it: https://admin.dns.example.com/#/logs?q=evil.example&status=blocked",
		Details: Details{Link: "https://admin.dns.example.com/#/logs?q=evil.example&status=blocked"}}
	b, err := e.alertEmail("alex@example.com", "https://admin.dns.example.com/alerts/unsubscribe/tok", a).bytes()
	if err != nil {
		t.Fatal(err)
	}
	p := parseEmail(t, string(b))

	if p.subject != title {
		t.Errorf("Subject decodes to %q, want %q", p.subject, title)
	}
	for line := range strings.SplitSeq(p.rawHeaders, "\r\n") {
		if len(line) > 78 {
			t.Errorf("header line of %d characters: %q", len(line), line)
		}
		if !isASCII(strings.ReplaceAll(line, "\t", " ")) {
			t.Errorf("header line isn't ASCII: %q", line)
		}
	}
	if p.header.Get("Bcc") != "" {
		t.Error("the body injected a header")
	}
	if from, err := (&mail.AddressParser{WordDecoder: new(mime.WordDecoder)}).Parse(p.header.Get("From")); err != nil || from.Name != "Família doh" || from.Address != "alerts@dns.example.com" {
		t.Errorf("From = %q: %v %v", p.header.Get("From"), from, err)
	}
	if _, err := p.header.Date(); err != nil {
		t.Errorf("Date: %v", err)
	}
	if id := p.header.Get("Message-ID"); !regexp.MustCompile(`^<[0-9a-f]{32}@dns\.example\.com>$`).MatchString(id) {
		t.Errorf("Message-ID = %q", id)
	}
	for k, want := range map[string]string{
		"To": "<alex@example.com>", "MIME-Version": "1.0", "Auto-Submitted": "auto-generated",
		"List-Unsubscribe": "<https://admin.dns.example.com/alerts/unsubscribe/tok>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
	} {
		if got := p.header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	if !strings.Contains(p.text, title) || !strings.Contains(p.text, "unsubscribe: https://admin.dns.example.com/alerts/unsubscribe/tok") {
		t.Errorf("text part:\n%s", p.text)
	}
	for _, bad := range []string{"<script", "<b>", "<img", "src=", "<style", "url(", "@import", "http://"} {
		if strings.Contains(p.html, bad) {
			t.Errorf("the HTML part has %q", bad)
		}
	}
	for _, want := range []string{
		`<html lang="en">`, "&lt;script&gt;", `<h1 `, `href="https://admin.dns.example.com/#/logs?q=evil.example&amp;status=blocked"`,
		`aria-hidden="true"`, `>Open in doh</a>`, "Ünïcödé", `name="color-scheme"`,
	} {
		if !strings.Contains(p.html, want) {
			t.Errorf("the HTML part lacks %q", want)
		}
	}
	if regexp.MustCompile(`href="(?:https?:)?//[^a]`).MatchString(p.html) {
		t.Error("the HTML links somewhere other than the origin")
	}
}

func TestFold(t *testing.T) {
	line := "Subject: " + encodeHeader(strings.Repeat("ü", 100))
	folded := fold(line)
	for l := range strings.SplitSeq(strings.TrimSuffix(folded, "\r\n"), "\r\n") {
		if len(l) > 78 {
			t.Errorf("line of %d: %q", len(l), l)
		}
	}
	if got := strings.ReplaceAll(folded, "\r\n ", " "); got != line+"\r\n" {
		t.Errorf("unfolding gives %q", got)
	}
	if got := encodeHeader("a\r\nb"); got != "a  b" {
		t.Errorf("encodeHeader kept a line break: %q", got)
	}
}

// TestEmail_DeliveredAfterConfirmation follows an email address from
// being added to its first alert: pending, confirmed by the code only
// its owner was sent, then sent alerts with a one-click unsubscribe link
// that works once.
func TestEmail_DeliveredAfterConfirmation(t *testing.T) {
	srv := newFakeSMTP(t, "mail.example.com")
	srv.mu.Lock()
	srv.user, srv.pass = "alerts", testPassword
	srv.mu.Unlock()
	var log bytes.Buffer
	e := mailEngine(t, srv, "smtp://alerts@mail.example.com", "https://admin.dns.example.com", &log)
	ctx := context.Background()

	d, secret, err := e.AddDestination(ctx, "smiths", NewDestination{Type: Email, Address: "Alex@Example.com", Name: "Alex"})
	if err != nil {
		t.Fatal(err)
	}
	if d.State != Pending || d.URL != "mailto:Alex@example.com" || secret != "" || d.ConfirmBy.IsZero() {
		t.Fatalf("added %+v", d)
	}
	msgs := srv.waitMessages(1)
	confirm := parseEmail(t, msgs[0].data)
	code := codeIn(t, confirm)
	if msgs[0].to != "Alex@example.com" || confirm.subject != "Confirm alerts from doh" || confirm.unsubscribe != "" {
		t.Errorf("confirmation email to %q: %q, unsubscribe %q", msgs[0].to, confirm.subject, confirm.unsubscribe)
	}
	link := "https://admin.dns.example.com/alerts/confirm/" + strings.ReplaceAll(code, "-", "")
	if !strings.Contains(confirm.text, link) || !strings.Contains(confirm.html, `href="`+link+`"`) {
		t.Errorf("no confirmation link %s:\n%s", link, confirm.text)
	}
	// Nothing a tenant chose is in it.
	if strings.Contains(confirm.text, "Alex\n") || strings.Contains(confirm.text, "smiths") {
		t.Errorf("the confirmation email has the tenant's words:\n%s", confirm.text)
	}

	// The code is never shown to whoever added the address: not in the
	// API's view, its JSON, the file, or the log.
	_, dests, _ := e.Get("smiths")
	j, _ := json.Marshal(dests)
	if strings.Contains(string(j), code) || strings.Contains(string(j), strings.ReplaceAll(code, "-", "")) || strings.Contains(log.String(), code) {
		t.Fatalf("the code shows: %s", j)
	}

	// Pending addresses get nothing, and don't count for tests.
	e.enqueue("smiths", e.stamp("smiths", e.words.test(time.Now())))
	if _, err := e.Test(ctx, "smiths"); !errors.Is(err, ErrNoDestinations) {
		t.Errorf("Test with only a pending address = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(srv.taken()); n != 1 {
		t.Fatalf("a pending address was sent %d emails", n)
	}

	// Forged and other tenants' codes don't confirm it.
	forged := newCode()
	for _, tt := range []struct{ scope, code string }{
		{"smiths", forged}, {"smiths", "not a code"}, {"smiths", ""}, {"jones", code}, {"", code},
	} {
		if _, err := e.Confirm(tt.scope, tt.code); !errors.Is(err, ErrNotFound) {
			t.Errorf("Confirm(%q, %q) = %v, want not found", tt.scope, tt.code, err)
		}
	}

	// The real one does, however it's typed, and only once.
	got, err := e.Confirm("smiths", strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil || got.State != Active || got.ID != d.ID || !got.ConfirmBy.IsZero() {
		t.Fatalf("Confirm = %+v, %v", got, err)
	}
	if _, err := e.Confirm("smiths", code); !errors.Is(err, ErrNotFound) {
		t.Errorf("replayed code = %v, want not found", err)
	}
	if _, _, err := e.ConfirmAny(code); !errors.Is(err, ErrNotFound) {
		t.Errorf("replayed code by link = %v, want not found", err)
	}

	// Now alerts are sent, with an unsubscribe link.
	results, err := e.Test(ctx, "smiths")
	if err != nil || len(results) != 1 || !results[0].OK {
		t.Fatalf("Test = %+v, %v", results, err)
	}
	alert := parseEmail(t, srv.waitMessages(2)[1].data)
	if alert.subject != "Test alert from doh" || !strings.HasPrefix(alert.unsubscribe, "https://admin.dns.example.com"+UnsubscribePath) {
		t.Fatalf("alert email: %q, unsubscribe %q", alert.subject, alert.unsubscribe)
	}
	token := strings.TrimPrefix(alert.unsubscribe, "https://admin.dns.example.com"+UnsubscribePath)

	if _, _, err := e.Unsubscribe(token + "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a forged token = %v", err)
	}
	scope, gone, err := e.Unsubscribe(token)
	if err != nil || scope != "smiths" || gone.ID != d.ID {
		t.Fatalf("Unsubscribe = %q, %+v, %v", scope, gone, err)
	}
	if _, _, err := e.Unsubscribe(token); !errors.Is(err, ErrNotFound) {
		t.Errorf("replayed unsubscribe = %v", err)
	}
	if _, dests, _ := e.Get("smiths"); len(dests) != 0 {
		t.Errorf("still there: %+v", dests)
	}
	if strings.Contains(log.String(), testPassword) {
		t.Error("the log shows the password")
	}
}

func TestEmail_ConfirmationExpires(t *testing.T) {
	srv := newFakeSMTP(t, "mail.example.com")
	e := mailEngine(t, srv, "smtp://mail.example.com", "", nil)
	d, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Email, Address: "alex@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	p := parseEmail(t, srv.waitMessages(1)[0].data)
	code := codeIn(t, p)
	if strings.Contains(p.text, "http") {
		t.Errorf("without an origin, the email has a link:\n%s", p.text)
	}

	// Past its time, the code is refused, and the address stays pending.
	e.store.mu.Lock()
	e.store.scopes[""].destinations[0].confirm.expires = time.Now().Add(-time.Second)
	e.store.mu.Unlock()
	if _, err := e.Confirm("", code); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired code = %v", err)
	}
	if _, dests, _ := e.Get(""); dests[0].State != Pending {
		t.Errorf("state = %s", dests[0].State)
	}

	// Adding it again sends a new code; the old one no longer works.
	again, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Email, Address: "alex@example.com"})
	if err != nil || again.ID != d.ID {
		t.Fatalf("adding again = %+v, %v", again, err)
	}
	fresh := codeIn(t, parseEmail(t, srv.waitMessages(2)[1].data))
	if _, err := e.Confirm("", code); !errors.Is(err, ErrNotFound) {
		t.Errorf("the old code = %v", err)
	}
	if _, err := e.Confirm("", fresh); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Email, Address: "alex@example.com"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("adding a confirmed address again = %v", err)
	}
}

func TestEmail_Limits(t *testing.T) {
	srv := newFakeSMTP(t, "mail.example.com")
	e := mailEngine(t, srv, "smtp://mail.example.com", "", nil)
	ctx := t.Context()
	add := func(scope, addr string) error {
		_, _, err := e.AddDestination(ctx, scope, NewDestination{Type: Email, Address: addr})
		return err
	}

	// At most MaxEmailDestinations addresses a scope, pending or not.
	for i := range MaxEmailDestinations {
		if err := add("a", fmt.Sprintf("p%d@example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := add("a", "one-more@example.com"); !errors.Is(err, ErrLimit) {
		t.Errorf("one address too many = %v", err)
	}

	// At most ConfirmEmailsPerScope confirmation emails a scope an hour:
	// resending to pending addresses counts.
	for i := MaxEmailDestinations; i < ConfirmEmailsPerScope; i++ {
		if err := add("a", "p0@example.com"); err != nil {
			t.Fatalf("resend %d: %v", i, err)
		}
	}
	if err := add("a", "p1@example.com"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("one confirmation email too many for a scope = %v", err)
	}

	// At most ConfirmEmailsPerAddress a day to one address, from every
	// scope together.
	for i := range ConfirmEmailsPerAddress {
		if err := add(fmt.Sprintf("s%d", i), "victim@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := add("another", "Victim@EXAMPLE.com"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("one confirmation email too many for an address = %v", err)
	}
	if n := len(srv.taken()); n != ConfirmEmailsPerScope+ConfirmEmailsPerAddress {
		t.Errorf("%d emails sent, want %d", n, ConfirmEmailsPerScope+ConfirmEmailsPerAddress)
	}

	// At most ConfirmAttemptsPerScope wrong codes an hour; then even the
	// right one waits.
	right := codeIn(t, parseEmail(t, srv.taken()[ConfirmEmailsPerScope].data))
	for range ConfirmAttemptsPerScope {
		if _, err := e.Confirm("s0", newCode()); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	if _, err := e.Confirm("s0", right); !errors.Is(err, ErrRateLimited) {
		t.Errorf("after too many wrong codes = %v", err)
	}
	if _, err := e.Confirm("s1", newCode()); !errors.Is(err, ErrNotFound) {
		t.Errorf("another scope is limited too: %v", err)
	}
}

func TestEmail_Unavailable(t *testing.T) {
	e, err := newEngine(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.AddDestination(t.Context(), "", NewDestination{Type: Email, Address: "alex@example.com"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("email without a mail server = %v", err)
	}
	if got := e.AvailableTypes(); len(got) != 3 || got[0] != Push {
		t.Errorf("AvailableTypes = %v", got)
	}
}

// TestEmail_NotSentNotKept checks that an address the confirmation never
// reached isn't kept, and the failure says why without the password.
func TestEmail_NotSentNotKept(t *testing.T) {
	srv := newFakeSMTP(t, "mail.example.com")
	srv.mu.Lock()
	srv.user, srv.pass = "alerts", testPassword
	srv.mu.Unlock()
	cfg := srv.config("smtp://alerts@mail.example.com")
	cfg.Password = "wrong"
	e, err := newEngine(Options{Mail: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = e.AddDestination(t.Context(), "", NewDestination{Type: Email, Address: "alex@example.com"})
	if !errors.Is(err, ErrNotSent) || !strings.Contains(err.Error(), "535") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("AddDestination = %v", err)
	}
	if _, dests, _ := e.Get(""); len(dests) != 0 {
		t.Errorf("kept %+v", dests)
	}
}

func TestEmail_PerAddressAlertLimit(t *testing.T) {
	srv := newFakeSMTP(t, "mail.example.com")
	e := mailEngine(t, srv, "smtp://mail.example.com", "", nil)
	d := destination{Destination: Destination{ID: "x", Type: Email}, url: "mailto:alex@example.com"}
	a := e.stamp("", e.words.test(time.Now()))
	for i := range EmailsPerAddress {
		if err := e.post(t.Context(), "", d, a); err != nil {
			t.Fatalf("email %d: %v", i, err)
		}
	}
	if err := e.post(t.Context(), "", d, a); !errors.Is(err, ErrRateLimited) || !isPermanent(err) {
		t.Errorf("one email too many = %v", err)
	}
}

func TestCode(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		c := newCode()
		if !regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$`).MatchString(c) || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
		if normalizeCode(c) != strings.ReplaceAll(c, "-", "") {
			t.Fatalf("normalizeCode(%q) = %q", c, normalizeCode(c))
		}
	}
	if normalizeCode("o1il0-abcde") != "0111"+"0ABCDE" {
		t.Errorf("look-alikes: %q", normalizeCode("o1il0-abcde"))
	}
	for _, bad := range []string{"", "ABCDE", "ABCDE-ABCDU", "ABCDE-ABCDE-A", "ÀBCDE-ABCDE", strings.Repeat("A", 100)} {
		if got := normalizeCode(bad); got != "" {
			t.Errorf("normalizeCode(%q) = %q", bad, got)
		}
	}
}
