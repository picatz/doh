// Package webui serves the admin web UI that "doh serve" exposes on its
// admin listener: a single page, with no build step or external assets,
// that manages profiles, browses the query log, and explains decisions
// through the admin API.
//
// The static files need no authentication. The page asks for an API token
// and sends it as a bearer token with every API request, so it holds no
// cookies and can't be driven by cross-site requests.
package webui

import (
	"embed"
	"github.com/picatz/doh/internal/httpsec"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed static
var static embed.FS

// ContentSecurityPolicy is the policy sent with every response. It allows
// only same-origin scripts, styles, API calls, web app manifest, and
// service worker, and no framing, inline code, or plugins; and with
// Trusted Types, the browser refuses to parse any string as HTML or
// script, so the UI's rule of building the DOM from elements and text is
// enforced, not only followed.
//
// One Trusted Types policy may exist, [ServiceWorkerPolicy]: registering
// a service worker takes a TrustedScriptURL. push.js creates it, with
// only createScriptURL, which allows nothing but [ServiceWorkerPath].
// Nothing can create HTML or script.
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; " +
	"manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; " +
	"require-trusted-types-for 'script'; trusted-types " + ServiceWorkerPolicy

// ServiceWorkerPolicy is the name of the one Trusted Types policy the UI
// may create: the one that lets it register its service worker.
const ServiceWorkerPolicy = "doh-sw"

// AssetPrefix is the path prefix of the UI's assets.
const AssetPrefix = "/ui/"

// ServiceWorkerPath is where the UI's service worker is served: at the
// root, so its scope is the whole UI without a Service-Worker-Allowed
// header.
const ServiceWorkerPath = "/sw.js"

// Handler serves the UI: GET / returns the page, GET /ui/{file} its
// embedded assets, among them its web app manifest and icons, and GET
// /sw.js its service worker. Every response carries strict security
// headers.
func Handler() http.Handler {
	files, err := fs.Sub(static, "static")
	if err != nil {
		panic(err) // the embedded directory always exists
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		serveFile(w, files, "index.html")
	})
	mux.HandleFunc("GET "+ServiceWorkerPath, func(w http.ResponseWriter, r *http.Request) {
		serveFile(w, files, "sw.js")
	})
	mux.HandleFunc("GET "+AssetPrefix+"{file}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		// The service worker is served only at the root: from /ui/ its
		// scope would be /ui/, which isn't where the UI is.
		if name == "index.html" || name == "sw.js" || strings.HasPrefix(name, ".") {
			http.NotFound(w, r)
			return
		}
		serveFile(w, files, name)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		httpsec.Page(h, r, ContentSecurityPolicy)
		h.Set("Cache-Control", "no-cache")
		mux.ServeHTTP(w, r)
	})
}

// serveFile writes the embedded file name, or a 404 if there isn't one.
func serveFile(w http.ResponseWriter, files fs.FS, name string) {
	b, err := fs.ReadFile(files, name)
	if err != nil {
		http.Error(w, "404 page not found", http.StatusNotFound)
		return
	}

	ctype := mime.TypeByExtension(path.Ext(name))
	switch path.Ext(name) {
	case ".js":
		ctype = "text/javascript; charset=utf-8"
	case ".svg":
		ctype = "image/svg+xml"
	case ".webmanifest":
		ctype = "application/manifest+json"
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	_, _ = w.Write(b)
}
