package webui

import (
	"bytes"
	"compress/gzip"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The UI's performance budget. The admin listener serves the embedded
// files as they are, uncompressed, to browsers on the same network, often
// from a Raspberry Pi over Wi-Fi: 384 KiB is under a third of a second at
// 10 Mbit/s, and leaves room to grow, but not to double, without someone
// deciding it's worth it here. The compressed limit holds behind a proxy
// that compresses, as most do. Fonts and images aren't fetched at all,
// except the app icons (PNG), which only a browser installing the app, or
// showing a notification, fetches: they have a budget of their own.
const (
	budgetBytes     = 384 << 10
	budgetGzipBytes = 112 << 10
	budgetModules   = 40
	budgetIconBytes = 64 << 10
)

// TestBudget checks the UI's scripts, styles, and page stay within the
// budget, so each feature pays for its weight.
func TestBudget(t *testing.T) {
	var all bytes.Buffer
	names, err := fs.Glob(static, "static/*")
	if err != nil {
		t.Fatal(err)
	}
	modules, icons := 0, 0
	for _, name := range names {
		b, err := fs.ReadFile(static, name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(name, ".png") {
			icons += len(b)
			continue
		}
		all.Write(b)
		if strings.HasSuffix(name, ".js") {
			modules++
		}
	}
	var gz bytes.Buffer
	w, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	w.Write(all.Bytes())
	w.Close()

	t.Logf("UI: %d KiB, %d KiB compressed, %d modules", all.Len()>>10, gz.Len()>>10, modules)
	if all.Len() > budgetBytes {
		t.Errorf("the UI is %d bytes, over its budget of %d", all.Len(), budgetBytes)
	}
	if gz.Len() > budgetGzipBytes {
		t.Errorf("the UI is %d bytes compressed, over its budget of %d", gz.Len(), budgetGzipBytes)
	}
	if icons > budgetIconBytes {
		t.Errorf("the app icons are %d bytes, over their budget of %d", icons, budgetIconBytes)
	}
	if modules > budgetModules {
		t.Errorf("the UI has %d modules, over its budget of %d requests", modules, budgetModules)
	}
}

// TestIndex_PreloadsEveryModule checks that the page preloads every module
// app.js imports, directly or not, so they're fetched at once instead of
// one level of imports at a time, and preloads nothing that isn't used.
func TestIndex_PreloadsEveryModule(t *testing.T) {
	html := readStatic(t, "index.html")
	var preloaded []string
	for _, m := range regexp.MustCompile(`<link rel="modulepreload" href="/ui/([^"]+)">`).FindAllStringSubmatch(html, -1) {
		preloaded = append(preloaded, m[1])
	}
	// Scripts the page loads itself are fetched at once anyway.
	for _, m := range regexp.MustCompile(`<script type="module" src="/ui/([^"]+)"></script>`).FindAllStringSubmatch(html, -1) {
		if m[1] != "app.js" {
			preloaded = append(preloaded, m[1])
		}
	}

	// Walk app.js's imports.
	imports := regexp.MustCompile(`(?m)^import [^;]*? from "\./([^"]+)";`)
	seen := map[string]bool{}
	var walk func(string)
	walk = func(name string) {
		for _, m := range imports.FindAllStringSubmatch(readStatic(t, name), -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				walk(m[1])
			}
		}
	}
	walk("app.js")
	var used []string
	for name := range seen {
		used = append(used, name)
	}
	slices.Sort(used)
	slices.Sort(preloaded)
	if !slices.Equal(used, preloaded) {
		t.Errorf("index.html preloads %v, want what app.js imports: %v", preloaded, used)
	}
}
