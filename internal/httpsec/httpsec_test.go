package httpsec

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPage(t *testing.T) {
	const csp = "default-src 'none'"
	for _, overTLS := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if overTLS {
			r.TLS = &tls.ConnectionState{}
		}
		h := http.Header{}
		Page(h, r, csp)
		for k, want := range map[string]string{
			"Content-Security-Policy":      csp,
			"X-Content-Type-Options":       "nosniff",
			"Referrer-Policy":              "no-referrer",
			"Cross-Origin-Resource-Policy": "same-origin",
			"Cross-Origin-Opener-Policy":   "same-origin",
			"X-Frame-Options":              "DENY",
			"Permissions-Policy":           PermissionsPolicy,
		} {
			if got := h.Get(k); got != want {
				t.Errorf("TLS %v: %s = %q, want %q", overTLS, k, got, want)
			}
		}
		// HSTS only over HTTPS: over HTTP, a man in the middle could send
		// it anyway, and it would pin a host that may not serve HTTPS.
		if got := h.Get("Strict-Transport-Security"); (got != "") != overTLS || (overTLS && got != HSTS) {
			t.Errorf("TLS %v: Strict-Transport-Security = %q", overTLS, got)
		}
	}
}

func TestDataHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	DataHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api", nil))
	h := rec.Header()
	if got := h.Get("Content-Security-Policy"); got != DataCSP || !strings.Contains(got, "sandbox") {
		t.Errorf("CSP = %q", got)
	}
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Errorf("headers = %v", h)
	}
}

func TestPermissionsPolicy(t *testing.T) {
	// Passkeys and the clipboard stay on, for this origin only; nothing
	// else is allowed anywhere.
	for _, part := range strings.Split(PermissionsPolicy, ", ") {
		feature, allow, ok := strings.Cut(part, "=")
		if !ok {
			t.Fatalf("malformed %q", part)
		}
		switch feature {
		case "publickey-credentials-create", "publickey-credentials-get", "clipboard-write":
			if allow != "(self)" {
				t.Errorf("%s=%s, want (self)", feature, allow)
			}
		default:
			if allow != "()" {
				t.Errorf("%s=%s, want ()", feature, allow)
			}
		}
	}
	for _, off := range []string{"camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()"} {
		if !strings.Contains(PermissionsPolicy, off) {
			t.Errorf("policy leaves %s on", off)
		}
	}
}

func TestStyleHash(t *testing.T) {
	// 'sha256-' and the base64 of the content's SHA-256, as from
	// printf 'body{color:red}' | openssl dgst -sha256 -binary | base64
	if got, want := StyleHash("body{color:red}"), "'sha256-FcQqt3aNlV7AZnGV4zkQRVeCeJOxbMPnQSx258L803E='"; got != want {
		t.Errorf("StyleHash = %q, want %q", got, want)
	}
	if StyleHash("a") == StyleHash("a ") {
		t.Error("whitespace changes no hash")
	}
	css, ok := InlineStyle("<head><style>p{}</style><style>q{}</style>")
	if !ok || css != "p{}" {
		t.Errorf("InlineStyle = %q, %v", css, ok)
	}
	for _, html := range []string{"", "<style>unclosed", "<p>none</p>"} {
		if _, ok := InlineStyle(html); ok {
			t.Errorf("InlineStyle(%q) found a style", html)
		}
	}
}
