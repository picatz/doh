package blocklist

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseSource(t *testing.T) {
	tests := []struct {
		in      string
		want    Source
		wantErr string
	}{
		{in: "default", want: Source{Name: DefaultPreset, Location: Presets[DefaultPreset]}},
		{in: "oisd-small", want: Source{Name: "oisd-small", Location: "https://small.oisd.nl"}},
		{in: "https://example.com/list.txt", want: Source{Name: "https://example.com/list.txt", Location: "https://example.com/list.txt"}},
		{in: "mine=https://example.com/list.txt", want: Source{Name: "mine", Location: "https://example.com/list.txt"}},
		{in: "local=/etc/doh/block.txt", want: Source{Name: "local", Location: "/etc/doh/block.txt"}},
		{in: "./block.txt", want: Source{Name: "./block.txt", Location: "./block.txt"}},
		{in: "", wantErr: "empty source"},
		{in: "mine=", wantErr: "no location"},
		{in: "oisd-tiny", wantErr: "unknown preset"},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			got, err := ParseSource(test.in)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got error %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("got %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestPresets(t *testing.T) {
	if _, ok := Presets[DefaultPreset]; !ok {
		t.Fatalf("default preset %q isn't a preset", DefaultPreset)
	}

	for name, url := range Presets {
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("preset %s isn't fetched over HTTPS: %s", name, url)
		}
	}
}

// listServer serves an Adblock Plus list with an ETag, counting full and
// conditional responses.
type listServer struct {
	*httptest.Server
	full, notModified atomic.Int32
	down              atomic.Bool
}

func newListServer(t *testing.T, body string) *listServer {
	t.Helper()

	s := &listServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}

		const etag = `"v1"`
		if r.Header.Get("If-None-Match") == etag {
			s.notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}

		s.full.Add(1)
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)

	return s
}

func TestLoader(t *testing.T) {
	server := newListServer(t, "||ads.example.com^\n")
	loader := &Loader{Client: server.Client(), CacheDir: filepath.Join(t.TempDir(), "cache")}
	sources := []Source{{Name: "remote", Location: server.URL}}

	load := func(t *testing.T) *List {
		t.Helper()

		list, err := loader.Load(t.Context(), sources, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if v := list.Lookup("x.ads.example.com"); !v.Blocked || v.Source != "remote" {
			t.Fatalf("got verdict %+v, want blocked by remote", v)
		}
		return list
	}

	t.Run("downloads and caches", func(t *testing.T) {
		load(t)

		if server.full.Load() != 1 {
			t.Errorf("got %d downloads, want 1", server.full.Load())
		}
	})

	t.Run("revalidates the cached copy", func(t *testing.T) {
		load(t)

		if server.full.Load() != 1 || server.notModified.Load() != 1 {
			t.Errorf("got %d downloads and %d not modified, want the cached copy revalidated", server.full.Load(), server.notModified.Load())
		}
	})

	t.Run("falls back to the cache when the server is down", func(t *testing.T) {
		server.down.Store(true)
		t.Cleanup(func() { server.down.Store(false) })

		load(t)
	})
}

func TestLoader_Sources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "hosts")
	if err := os.WriteFile(file, []byte("0.0.0.0 tracker.example.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	broken := newListServer(t, "")
	broken.down.Store(true)

	loader := &Loader{Client: broken.Client()}

	t.Run("file, failing source, and config rules", func(t *testing.T) {
		list, err := loader.Load(t.Context(),
			[]Source{{Name: "file", Location: file}, {Name: "broken", Location: broken.URL}},
			[]string{"blocked.example"}, []string{"tracker.example.net"},
		)
		if err != nil {
			t.Fatal(err)
		}

		if v := list.Lookup("tracker.example.net"); v.Blocked || v.Source != "config" {
			t.Errorf("got %+v, want the config allow rule to win", v)
		}
		if v := list.Lookup("a.blocked.example"); !v.Blocked || v.Source != "config" {
			t.Errorf("got %+v, want blocked by config", v)
		}
	})

	t.Run("every source failing is an error", func(t *testing.T) {
		if _, err := loader.Load(t.Context(), []Source{{Name: "broken", Location: broken.URL}}, nil, nil); err == nil {
			t.Error("expected an error when no source loads")
		}
	})

	t.Run("no sources", func(t *testing.T) {
		list, err := loader.Load(t.Context(), nil, []string{"blocked.example"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !list.Lookup("blocked.example").Blocked {
			t.Error("config block rule missing")
		}
	})
}

func TestLoader_RejectsOversizedLists(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("||a.example^\n", 1024)))
	}))
	t.Cleanup(server.Close)

	loader := &Loader{Client: server.Client(), MaxSize: 1024}
	if _, err := loader.Load(t.Context(), []Source{{Name: "huge", Location: server.URL}}, nil, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("got error %v, want the list rejected as too large", err)
	}
}

func TestParseSource_PublicName(t *testing.T) {
	src, err := ParseSource("https://user:secret@lists.example/block.txt?token=hunter2")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(src.Name, "secret") || strings.Contains(src.Name, "hunter2") {
		t.Errorf("name %q exposes credentials", src.Name)
	}
	if src.Name != "https://lists.example/block.txt" {
		t.Errorf("got name %q", src.Name)
	}
	if src.Location != "https://user:secret@lists.example/block.txt?token=hunter2" {
		t.Errorf("location %q lost its credentials", src.Location)
	}
}

func TestLoader_ConcurrentCacheWrites(t *testing.T) {
	server := newListServer(t, "||ads.example.com^\n")
	cacheDir := t.TempDir()

	errs := make(chan error, 8)
	for range cap(errs) {
		go func() {
			loader := &Loader{Client: server.Client(), CacheDir: cacheDir}
			_, err := loader.Load(t.Context(), []Source{{Name: "remote", Location: server.URL}}, nil, nil)
			errs <- err
		}()
	}
	for range cap(errs) {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || strings.HasSuffix(entries[0].Name(), ".tmp") {
		t.Fatalf("got cache entries %v, want one complete file", entries)
	}

	// The cached copy alone, with the server down, must still load.
	server.down.Store(true)
	list, err := (&Loader{Client: server.Client(), CacheDir: cacheDir}).Load(t.Context(), []Source{{Name: "remote", Location: server.URL}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !list.Lookup("ads.example.com").Blocked {
		t.Error("cached list lost its rules")
	}
}

func TestLoader_RejectsOversizedFiles(t *testing.T) {
	file := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(file, []byte(strings.Repeat("||a.example^\n", 100)), 0o600); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{MaxSize: 64}
	if _, err := loader.Load(t.Context(), []Source{{Name: "file", Location: file}}, nil, nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("got error %v, want an oversized file rejected rather than truncated", err)
	}
}
