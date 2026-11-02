package webui

import (
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// TestInstallable checks what makes the UI an installable web app: its
// manifest, served as one, naming icons that exist at the sizes it says,
// and its service worker, served at the root and nowhere else.
func TestInstallable(t *testing.T) {
	rec := get(t, "/ui/manifest.webmanifest")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/manifest+json" {
		t.Fatalf("manifest: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	checkSecurityHeaders(t, rec.Header())
	var m struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		ShortName       string `json:"short_name"`
		StartURL        string `json:"start_url"`
		Scope           string `json:"scope"`
		Display         string `json:"display"`
		ThemeColor      string `json:"theme_color"`
		BackgroundColor string `json:"background_color"`
		Icons           []struct {
			Src, Sizes, Type, Purpose string
		} `json:"icons"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Name != "doh" || m.ShortName != "doh" || m.ID != "/" || m.StartURL != "/" || m.Scope != "/" || m.Display != "standalone" {
		t.Errorf("manifest = %+v", m)
	}
	css := readStatic(t, "app.css")
	for _, c := range []string{m.ThemeColor, m.BackgroundColor} {
		if c == "" || !strings.Contains(css, c) {
			t.Errorf("manifest color %q isn't one of the UI's tokens", c)
		}
	}
	purposes := map[string]bool{}
	for _, icon := range m.Icons {
		purposes[icon.Purpose+" "+icon.Sizes] = true
		rec := get(t, icon.Src)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != icon.Type {
			t.Errorf("%s: %d %q, want %s", icon.Src, rec.Code, rec.Header().Get("Content-Type"), icon.Type)
			continue
		}
		if icon.Type == "image/png" {
			cfg, err := png.DecodeConfig(rec.Body)
			if err != nil || fmt.Sprintf("%dx%d", cfg.Width, cfg.Height) != icon.Sizes {
				t.Errorf("%s is %dx%d, %v; the manifest says %s", icon.Src, cfg.Width, cfg.Height, err, icon.Sizes)
			}
		}
	}
	for _, need := range []string{"any 192x192", "any 512x512", "maskable 512x512"} {
		if !purposes[need] {
			t.Errorf("no %s icon", need)
		}
	}
	for path, size := range map[string]int{"/ui/apple-touch-icon.png": 180, "/ui/badge-96.png": 96} {
		cfg, err := png.DecodeConfig(get(t, path).Body)
		if err != nil || cfg.Width != size || cfg.Height != size {
			t.Errorf("%s: %+v, %v", path, cfg, err)
		}
	}

	index := readStatic(t, "index.html")
	for _, want := range []string{`<link rel="manifest" href="/ui/manifest.webmanifest">`, `<link rel="apple-touch-icon" href="/ui/apple-touch-icon.png">`, `<meta name="theme-color"`} {
		if !strings.Contains(index, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}

	rec = get(t, ServiceWorkerPath)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || !strings.Contains(rec.Body.String(), `addEventListener("push"`) {
		t.Fatalf("service worker: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	checkSecurityHeaders(t, rec.Header())
	if rec := get(t, "/ui/sw.js"); rec.Code != http.StatusNotFound {
		t.Errorf("/ui/sw.js = %d; served there, its scope would be /ui/", rec.Code)
	}
}

// TestCSP_OneTrustedTypesPolicy checks that the CSP allows exactly one
// Trusted Types policy, which push.js creates once, to register the
// service worker, with only createScriptURL, for the worker's URL: no
// policy can turn strings into HTML or script.
func TestCSP_OneTrustedTypesPolicy(t *testing.T) {
	for _, need := range []string{"require-trusted-types-for 'script'", "trusted-types " + ServiceWorkerPolicy + ";", "manifest-src 'self'", "worker-src 'self'"} {
		if !strings.Contains(ContentSecurityPolicy+";", need) {
			t.Errorf("CSP lacks %q", need)
		}
	}
	for _, bad := range []string{"'allow-duplicates'", "trusted-types default", "trusted-types *"} {
		if strings.Contains(ContentSecurityPolicy, bad) {
			t.Errorf("CSP has %q", bad)
		}
	}
	js := readScripts(t)
	if n := strings.Count(js, "createPolicy("); n != 1 {
		t.Fatalf("createPolicy is called %d times, want once, in push.js", n)
	}
	push := readStatic(t, "push.js")
	if !strings.Contains(push, `export const POLICY = "`+ServiceWorkerPolicy+`"`) || !strings.Contains(push, `export const SW_URL = "`+ServiceWorkerPath+`"`) {
		t.Error("push.js doesn't name the CSP's policy and the worker's path")
	}
	rules := regexp.MustCompile(`(?s)createPolicy\(POLICY, \{(.*?)\n    \}\);`).FindStringSubmatch(push)
	if rules == nil || strings.Contains(rules[1], "createHTML") || strings.Contains(rules[1], "createScript(") ||
		!strings.Contains(rules[1], "if (url !== SW_URL) throw") {
		t.Errorf("push.js's policy rules: %q", rules)
	}
}
