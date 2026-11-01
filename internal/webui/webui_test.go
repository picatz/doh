package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHandler_ServesFilesWithSecurityHeaders(t *testing.T) {
	tests := []struct {
		path, contentType string
	}{
		{"/", "text/html; charset=utf-8"},
		{"/ui/app.js", "text/javascript; charset=utf-8"},
		{"/ui/app.css", "text/css; charset=utf-8"},
		{"/ui/icon.svg", "image/svg+xml"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := get(t, tt.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != tt.contentType {
				t.Errorf("Content-Type = %q, want %q", got, tt.contentType)
			}
			if rec.Body.Len() == 0 {
				t.Error("empty body")
			}
			checkSecurityHeaders(t, rec.Header())
		})
	}
}

func checkSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":    ContentSecurityPolicy,
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"X-Frame-Options":            "DENY",
		"Cache-Control":              "no-cache",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestHandler_NotFound(t *testing.T) {
	for _, path := range []string{"/ui/missing.js", "/ui/index.html", "/ui/.hidden", "/other", "/ui/../webui.go"} {
		t.Run(path, func(t *testing.T) {
			rec := get(t, path)
			// ServeMux redirects unclean paths to their clean form rather
			// than serving anything for them.
			if rec.Code == http.StatusOK || rec.Code < 300 {
				t.Fatalf("status = %d, want 404 or a redirect", rec.Code)
			}
			// Even errors carry the security headers.
			if rec.Code == http.StatusNotFound {
				checkSecurityHeaders(t, rec.Header())
			}
		})
	}
}

func TestHandler_RejectsOtherMethods(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want 405", rec.Code)
	}
}

func TestCSP_IsStrict(t *testing.T) {
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "*", "http:", "https:", "data: 'self'; script"} {
		if strings.Contains(ContentSecurityPolicy, bad) {
			t.Errorf("CSP contains %q", bad)
		}
	}
	for _, need := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(ContentSecurityPolicy, need) {
			t.Errorf("CSP lacks %q", need)
		}
	}
}

func readStatic(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(static, "static/"+name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestIndex_NoInlineCodeOrExternalAssets(t *testing.T) {
	html := readStatic(t, "index.html")

	checks := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"inline script", regexp.MustCompile(`(?is)<script\b[^>]*>\s*[^<\s]`)},
		{"style element", regexp.MustCompile(`(?i)<style\b`)},
		{"style attribute", regexp.MustCompile(`(?i)\sstyle\s*=`)},
		{"event handler attribute", regexp.MustCompile(`(?i)\son[a-z]+\s*=`)},
		{"javascript: URL", regexp.MustCompile(`(?i)javascript:`)},
		{"absolute URL", regexp.MustCompile(`(?i)(?:src|href)\s*=\s*"(?:https?:)?//`)},
	}
	for _, c := range checks {
		if loc := c.re.FindStringIndex(html); loc != nil {
			t.Errorf("index.html has %s: %q", c.name, html[loc[0]:min(loc[1]+20, len(html))])
		}
	}

	for _, tag := range regexp.MustCompile(`(?i)<script\b[^>]*>`).FindAllString(html, -1) {
		if !strings.Contains(tag, ` src="`) {
			t.Errorf("index.html has a script without src: %s", tag)
		}
	}

	// Every referenced asset is same-origin under /ui/ and exists.
	refs := regexp.MustCompile(`(?:src|href)="([^"#]+)"`).FindAllStringSubmatch(html, -1)
	if len(refs) == 0 {
		t.Fatal("index.html references no assets")
	}
	for _, m := range refs {
		ref := m[1]
		if !strings.HasPrefix(ref, AssetPrefix) {
			t.Errorf("index.html references %q, want a path under %s", ref, AssetPrefix)
			continue
		}
		if rec := get(t, ref); rec.Code != http.StatusOK {
			t.Errorf("referenced asset %q: status %d", ref, rec.Code)
		}
	}
}

func TestScript_NoUnsafeDOMOrDynamicCode(t *testing.T) {
	js := readStatic(t, "app.js")

	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "setInterval(", "srcdoc"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js uses %q", bad)
		}
	}

	// The only absolute URL the script builds is the DoH URL it shows for
	// a profile; it never fetches anything off-origin.
	urls := regexp.MustCompile(`https?://[^\s"'`+"`"+`]*`).FindAllString(js, -1)
	for _, u := range urls {
		if u != "https://${host}/dns-query/${id}" && u != "https://example.com/list.txt" {
			t.Errorf("app.js contains URL %q", u)
		}
	}
	if regexp.MustCompile(`fetch\(\s*["'` + "`" + `]https?:`).MatchString(js) {
		t.Error("app.js fetches an absolute URL")
	}

	// Tokens live in sessionStorage only, never in localStorage or cookies.
	for _, bad := range []string{"localStorage", "document.cookie"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js uses %s", bad)
		}
	}
}

func TestStylesheet_NoExternalResources(t *testing.T) {
	css := readStatic(t, "app.css")
	for _, bad := range []string{"@import", "url(http", "url(//", "expression("} {
		if strings.Contains(css, bad) {
			t.Errorf("app.css contains %q", bad)
		}
	}
}

func TestIcon_NoScript(t *testing.T) {
	svg := readStatic(t, "icon.svg")
	for _, bad := range []string{"<script", "onload", "href="} {
		if strings.Contains(strings.ToLower(svg), bad) {
			t.Errorf("icon.svg contains %q", bad)
		}
	}
}

// TestScript_TokenOnlyInAuthorizationHeader checks that the API token is
// only ever sent in the Authorization header, never in a URL, where it
// would end up in logs, history, and Referer headers. Downloads, such as
// configuration profiles, are fetched with the header and saved through
// object URLs instead.
func TestScript_TokenOnlyInAuthorizationHeader(t *testing.T) {
	js := readStatic(t, "app.js")

	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`[?&](access_)?token=`),
		regexp.MustCompile(`(href|src|location(\.href)?)\s*[:=][^;\n]*state\.token`),
		regexp.MustCompile(`window\.open\(`),
	} {
		if loc := re.FindStringIndex(js); loc != nil {
			t.Errorf("app.js may put the token in a URL: %q", js[loc[0]:min(loc[1]+40, len(js))])
		}
	}

	if got := strings.Count(js, "state.token"); got == 0 || !strings.Contains(js, "Authorization: `Bearer ${state.token}`") {
		t.Error("app.js doesn't send the token as a bearer token")
	}
	if !strings.Contains(js, "URL.revokeObjectURL") {
		t.Error("object URLs for downloads aren't revoked")
	}
}
