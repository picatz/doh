package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
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

// readScripts returns every embedded script, joined.
func readScripts(t *testing.T) string {
	t.Helper()
	names, err := fs.Glob(static, "static/*.js")
	if err != nil || len(names) < 2 {
		t.Fatalf("scripts = %q, %v", names, err)
	}
	var all strings.Builder
	for _, name := range names {
		all.WriteString(readStatic(t, strings.TrimPrefix(name, "static/")))
	}
	return all.String()
}

func TestScript_NoUnsafeDOMOrDynamicCode(t *testing.T) {
	js := readScripts(t)

	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "setInterval(", "srcdoc"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js uses %q", bad)
		}
	}

	// The only absolute URL the script builds is the DoH URL it shows for
	// a profile; it never fetches anything off-origin. The SVG namespace
	// is a name, never fetched.
	urls := regexp.MustCompile(`https?://[^\s"'`+"`"+`]*`).FindAllString(js, -1)
	for _, u := range urls {
		switch u {
		case "https://${host}/dns-query/${id}", "https://example.com/list.txt", "http://www.w3.org/2000/svg":
		case "https://ntfy.sh/", "https://example.com/hooks/doh":
			// Suggested and example destinations for alerts, never fetched.
		default:
			t.Errorf("app.js contains URL %q", u)
		}
	}
	if regexp.MustCompile(`fetch\(\s*["'` + "`" + `]https?:`).MatchString(js) {
		t.Error("app.js fetches an absolute URL")
	}

	// Session cookies are HttpOnly. The only thing stored in the browser
	// is the theme someone chose, by theme.js, under one key.
	for _, bad := range []string{"sessionStorage", "indexedDB", "document.cookie"} {
		if strings.Contains(js, bad) {
			t.Errorf("a script uses %s", bad)
		}
	}
	for _, name := range []string{"app.js", "format.js", "palette.js", "schedule.js"} {
		if strings.Contains(readStatic(t, name), "localStorage") {
			t.Errorf("%s uses localStorage; only theme.js stores anything", name)
		}
	}
	theme := readStatic(t, "theme.js")
	if keys := regexp.MustCompile(`const KEY = "([^"]+)"`).FindAllStringSubmatch(theme, -1); len(keys) != 1 || keys[0][1] != "doh.theme" {
		t.Errorf("theme.js stores under %v, want only doh.theme", keys)
	}
	if strings.Count(theme, "localStorage.") != 3 || strings.Count(theme, "localStorage.setItem(KEY") != 1 {
		t.Error("theme.js stores something besides the theme")
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

// TestScript_HoldsNoToken checks that the UI never handles an API token:
// it relies on the server's HttpOnly session cookie, so a script injected
// into the page couldn't steal a long-lived credential, and sign-in link
// codes are removed from the address bar as soon as the page loads.
func TestScript_HoldsNoToken(t *testing.T) {
	js := readScripts(t)
	html := readStatic(t, "index.html")

	for _, bad := range []string{"Authorization", "Bearer", "state.token", "#token=", `type="password"`} {
		if strings.Contains(js, bad) || strings.Contains(html, bad) {
			t.Errorf("the UI still handles API tokens: it contains %q", bad)
		}
	}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`[?&](access_)?token=`),
		regexp.MustCompile(`window\.open\(`),
	} {
		if loc := re.FindStringIndex(js); loc != nil {
			t.Errorf("app.js may put a credential in a URL: %q", js[loc[0]:min(loc[1]+40, len(js))])
		}
	}

	if got := strings.Count(js, `credentials: "same-origin"`); got < 2 {
		t.Errorf("app.js sets same-origin credentials on %d fetches, want the API and sign-in calls", got)
	}
	if !regexp.MustCompile(`signin=[^\n]*\n[^\n]*\n[^\n]*history\.replaceState`).MatchString(js) {
		t.Error("app.js doesn't remove sign-in link codes from the address bar right away")
	}
	if !strings.Contains(js, "URL.revokeObjectURL") {
		t.Error("object URLs for downloads aren't revoked")
	}
}

// TestScript_PasskeyFallbacks checks that passkeys work in browsers without
// the WebAuthn Level 3 JSON helpers, through one isolated converter.
func TestScript_PasskeyFallbacks(t *testing.T) {
	js := readStatic(t, "app.js")
	for _, want := range []string{"parseCreationOptionsFromJSON", "parseRequestOptionsFromJSON", "toJSON", "getClientExtensionResults"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	if n := strings.Count(js, "PublicKeyCredential"); n != 1 {
		t.Errorf("PublicKeyCredential is used %d times, want once, inside the converter", n)
	}
}

// TestIndex_OperatorOnlyStartsHidden checks that what only the server's
// operator may use starts hidden, so tenants never glimpse it before the
// script learns who they are.
func TestIndex_OperatorOnlyStartsHidden(t *testing.T) {
	index := readStatic(t, "index.html")
	for _, id := range []string{"nav-tenants", "c-tenant-row", "sa-tenant-row", "view-tenants"} {
		tag := regexp.MustCompile(`<[a-z]+[^>]*\sid="` + id + `"[^>]*>`).FindString(index)
		if !regexp.MustCompile(`\shidden[\s>]`).MatchString(tag) {
			t.Errorf("#%s doesn't start hidden: %q", id, tag)
		}
	}
}

// TestScriptModules runs the script modules' own tests, if node is
// installed: among them, that "active now" agrees with the server's
// schedule semantics, and that times read as people would say them.
func TestScriptModules(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node isn't installed")
	}
	tests, err := filepath.Glob(filepath.Join("testdata", "*_test.mjs"))
	if err != nil || len(tests) == 0 {
		t.Fatalf("no module tests: %v", err)
	}
	for _, file := range tests {
		t.Run(filepath.Base(file), func(t *testing.T) {
			out, err := exec.CommandContext(t.Context(), node, "--test", file).CombinedOutput()
			if err != nil {
				t.Fatalf("node --test %s: %v\n%s", file, err, out)
			}
		})
	}
	for _, module := range []string{"/ui/schedule.js", "/ui/format.js"} {
		if rec := get(t, module); rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
			t.Errorf("%s: %d %q", module, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}

// TestScript_SchedulesFollowTheProfileTimeZone checks that whether a
// schedule is in effect is computed in the profile's time zone, in one
// place, and that the time zone picker works without Intl.supportedValuesOf.
func TestScript_SchedulesFollowTheProfileTimeZone(t *testing.T) {
	js := readStatic(t, "app.js")
	mod := readStatic(t, "schedule.js")
	if n := strings.Count(js+mod, "Intl.DateTimeFormat(\"en-US\""); n != 1 || !strings.Contains(mod, "timeZone, weekday") {
		t.Error("schedules aren't checked in the profile's time zone by one function")
	}
	if !strings.Contains(js, `import { WEEKDAYS`) || !strings.Contains(js, `from "./schedule.js"`) {
		t.Error("app.js doesn't use schedule.js")
	}
	if !regexp.MustCompile(`try \{ zones = Intl\.supportedValuesOf\("timeZone"\); \} catch`).MatchString(js) {
		t.Error("the time zone picker has no fallback for browsers without Intl.supportedValuesOf")
	}
	if rec := get(t, "/ui/schedule.js"); rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Errorf("/ui/schedule.js: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}
