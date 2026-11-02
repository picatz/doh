// Package httpsec sets the response headers that limit what a browser
// lets a response do, so every surface doh serves (its web UI, its API,
// sign-in, and setup pages) gets the same defenses in depth, from one
// tested place.
//
// Each header backs up something the code already avoids, so a mistake
// in one place isn't enough to hurt anyone:
//
//   - A Content-Security-Policy that allows no inline code, nothing from
//     elsewhere, no framing, and, for pages that ask, Trusted Types,
//     which make the browser refuse to turn strings into HTML or script.
//   - Permissions-Policy, which turns off every powerful feature a page
//     doesn't use: only passkeys and the clipboard stay on.
//   - Cross-Origin-Resource-Policy and -Opener-Policy, which keep other
//     sites from loading doh's responses or reaching into its windows.
//   - Strict-Transport-Security over HTTPS, so browsers never fall back to
//     plain HTTP.
//   - nosniff and no-referrer, so responses are only ever what they say,
//     and URLs never leak to other sites.
package httpsec

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

// PermissionsPolicy turns off the powerful features doh never uses, and
// keeps the two it does (passkeys and copying to the clipboard) to its
// own origin ([Permissions Policy]).
//
// [Permissions Policy]: https://www.w3.org/TR/permissions-policy/
const PermissionsPolicy = "accelerometer=(), autoplay=(), camera=(), display-capture=(), " +
	"encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), " +
	"microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), serial=(), " +
	"usb=(), xr-spatial-tracking=(), " +
	"publickey-credentials-create=(self), publickey-credentials-get=(self), clipboard-write=(self)"

// HSTS is the Strict-Transport-Security sent over HTTPS: two years, the
// length browsers' preload lists ask for ([RFC 6797]). It leaves out
// includeSubDomains, since doh can't speak for the rest of its domain.
//
// [RFC 6797]: https://www.rfc-editor.org/rfc/rfc6797.html
const HSTS = "max-age=63072000"

// TrustedTypes is the CSP directives that make the browser refuse to
// parse strings as HTML or script, through innerHTML, eval, and the like,
// and that allow no policy to get around it ([Trusted Types]).
//
// [Trusted Types]: https://www.w3.org/TR/trusted-types/
const TrustedTypes = "require-trusted-types-for 'script'; trusted-types 'none'"

// DataCSP is the policy for responses that are data, such as JSON: a
// browser that opens one directly renders nothing active.
const DataCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox"

// common sets the headers every response gets.
func common(h http.Header, r *http.Request) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", PermissionsPolicy)
	if r != nil && r.TLS != nil {
		h.Set("Strict-Transport-Security", HSTS)
	}
}

// Page sets the headers for an HTML page, or one of its assets, under
// the content security policy csp, which should forbid framing.
func Page(h http.Header, r *http.Request, csp string) {
	common(h, r)
	h.Set("Content-Security-Policy", csp)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY") // for browsers before frame-ancestors
}

// Data sets the headers for a response that's data, not a page.
func Data(h http.Header, r *http.Request) {
	common(h, r)
	h.Set("Content-Security-Policy", DataCSP)
}

// DataHandler wraps next so each response gets [Data]'s headers.
func DataHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Data(w.Header(), r)
		next.ServeHTTP(w, r)
	})
}

// StyleHash returns a CSP source that allows exactly one inline <style>
// element, by the SHA-256 of its contents ([CSP 3, hash sources]).
//
// [CSP 3, hash sources]: https://www.w3.org/TR/CSP3/#grammardef-hash-source
func StyleHash(css string) string {
	sum := sha256.Sum256([]byte(css))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// InlineStyle returns the contents of the first <style> element in html,
// and whether there is one, for [StyleHash].
func InlineStyle(html string) (string, bool) {
	_, rest, ok := strings.Cut(html, "<style>")
	if !ok {
		return "", false
	}
	css, _, ok := strings.Cut(rest, "</style>")
	return css, ok
}
