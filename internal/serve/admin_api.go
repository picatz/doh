package serve

import (
	"bytes"
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"mime"
	"net/http"
	"net/netip"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/filter"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
)

// maxAPIBody bounds API request bodies.
const maxAPIBody = 1 << 20

// streamHeartbeat is how often the log stream sends a comment, so proxies
// and clients don't time out an idle stream.
const streamHeartbeat = 15 * time.Second

// apiHandler returns the admin API, under [api.Prefix].
func (s *Server) apiHandler() http.Handler {
	mux := http.NewServeMux()
	p := api.Prefix

	mux.HandleFunc("GET "+p+"/status", s.apiStatus)
	mux.HandleFunc("GET "+p+"/catalog", s.apiCatalog)
	mux.HandleFunc("GET "+p+"/policy", s.apiGetPolicy)
	mux.HandleFunc("PUT "+p+"/policy", s.apiPutPolicy)
	mux.HandleFunc("GET "+p+"/profiles", s.apiListProfiles)
	mux.HandleFunc("POST "+p+"/profiles", s.apiCreateProfile)
	mux.HandleFunc("GET "+p+"/profiles/{id}", s.apiGetProfile)
	mux.HandleFunc("PATCH "+p+"/profiles/{id}", s.apiPatchProfile)
	mux.HandleFunc("DELETE "+p+"/profiles/{id}", s.apiDeleteProfile)
	mux.HandleFunc("POST "+p+"/profiles/{id}/allow", s.apiDomain(true, true))
	mux.HandleFunc("DELETE "+p+"/profiles/{id}/allow/{domain}", s.apiDomain(true, false))
	mux.HandleFunc("POST "+p+"/profiles/{id}/deny", s.apiDomain(false, true))
	mux.HandleFunc("DELETE "+p+"/profiles/{id}/deny/{domain}", s.apiDomain(false, false))
	mux.HandleFunc("GET "+p+"/logs", s.apiLogs)
	mux.HandleFunc("GET "+p+"/logs/stream", s.apiStream)
	mux.HandleFunc("GET "+p+"/stats", s.apiStats)
	mux.HandleFunc("GET "+p+"/explain", s.apiExplain)
	mux.HandleFunc("POST "+p+"/signin-links", s.apiSigninLink)
	mux.HandleFunc("GET "+p+"/people", s.apiPeople)
	mux.HandleFunc("DELETE "+p+"/people/{id}", s.apiDeletePerson)
	mux.HandleFunc("DELETE "+p+"/people/{id}/passkeys/{passkey}", s.apiDeletePasskey)
	mux.HandleFunc("GET "+p+"/profiles/{id}/setup", s.apiSetup)
	mux.HandleFunc("GET "+p+"/profiles/{id}/apple.mobileconfig", s.apiMobileConfig)
	mux.HandleFunc(p+"/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "no such endpoint")
	})

	return s.authorize(mux)
}

// authorize requires a bearer token ([RFC 6750, Section 2.1]): any token
// for GET requests, and an admin token for everything else.
//
// [RFC 6750, Section 2.1]: https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		if !s.tokens.enabled() {
			writeError(w, http.StatusServiceUnavailable, "the admin API needs a data directory (--data-dir) or an admin token file")
			return
		}

		// A bearer token, from the CLI or automation, or a browser's
		// signed-in session.
		role := s.sessionRole(r)
		if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			role = s.tokens.roleOf(strings.TrimSpace(token))
		}

		switch {
		case role == roleNone:
			w.Header().Set("WWW-Authenticate", `Bearer realm="doh"`)
			writeError(w, http.StatusUnauthorized, "sign in, or send a valid bearer token")
		case role == roleReader && r.Method != http.MethodGet && r.Method != http.MethodHead:
			w.Header().Set("WWW-Authenticate", `Bearer realm="doh", error="insufficient_scope"`)
			writeError(w, http.StatusForbidden, "this token can only read; use the admin token to make changes")
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// writeJSON writes v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v, json.FormatNilSliceAsNull(false), json.FormatNilMapAsNull(false))
	_, _ = io.WriteString(w, "\n")
}

// writeError writes an [api.Error].
func writeError(w http.ResponseWriter, status int, msg string, details ...string) {
	writeJSON(w, status, api.Error{Error: msg, Details: details})
}

// writePolicyError reports why a policy was rejected, listing each
// problem separately.
func writePolicyError(w http.ResponseWriter, err error) {
	msg := strings.TrimPrefix(err.Error(), "policy: ")
	details := strings.Split(msg, "\n")
	if len(details) == 1 {
		writeError(w, http.StatusBadRequest, "invalid policy: "+msg)
		return
	}
	writeError(w, http.StatusBadRequest, "invalid policy", details...)
}

// decode reads a JSON request body into v, rejecting unknown fields.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAPIBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	if err := json.Unmarshal(b, v, json.RejectUnknownMembers(true)); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	engine := s.engine.Load()
	pol := engine.Policy()

	status := api.Status{
		Hostname:  s.config.Hostname,
		Version:   version(),
		Started:   s.started,
		Upstreams: s.config.Upstreams,
		Lists:     s.lists.Status(),
		Queries:   s.telemetry.totals(),
	}
	s.listenersMu.Lock()
	status.Listeners = maps.Clone(s.listeners)
	s.listenersMu.Unlock()

	if s.store != nil {
		status.Policy = s.store.status()
	} else {
		status.Policy.ReadOnly = true
	}
	status.Policy.ETag = pol.ETag()
	status.Policy.Profiles = len(pol.Profiles)

	if s.qlog != nil {
		status.QueryLog = api.QueryLogStatus{Enabled: true, Entries: s.qlog.Len()}
		if s.config.DataDir != "" {
			status.QueryLog.Dir = filepath.Join(s.config.DataDir, "querylog")
			status.QueryLog.Retention = time.Duration(cmp.Or(s.config.QueryLog.Retention, Duration(querylog.DefaultRetention))).String()
		}
	}

	writeJSON(w, http.StatusOK, status)
}

func (s *Server) apiCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, api.Catalog{Features: filter.Features(), Presets: blocklist.Catalog})
}

func (s *Server) apiGetPolicy(w http.ResponseWriter, r *http.Request) {
	p := s.engine.Load().Policy()
	etag := p.ETag()
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// etagMatches reports whether a conditional header's list of entity tags
// includes etag, or is "*" ([RFC 9110, Section 13.1.1]).
//
// [RFC 9110, Section 13.1.1]: https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.1
func etagMatches(header, etag string) bool {
	for tag := range strings.SplitSeq(header, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "*" || strings.TrimPrefix(tag, "W/") == etag {
			return true
		}
	}
	return false
}

// errNotFound reports a profile that doesn't exist.
var errNotFound = errors.New("not found")

// updatePolicy applies change to a copy of the current policy, then
// validates, saves, and applies the result, writing any error. It honors
// If-Match, so concurrent editors can't overwrite each other's changes.
func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, change func(*policy.Policy) error) (*policy.Policy, bool) {
	if s.store == nil {
		writeError(w, http.StatusConflict, "the policy is read-only: profiles are off, so only the blocklist settings apply (run with a data directory or --policy to enable them)")
		return nil, false
	}
	if s.store.readOnly() {
		writeError(w, http.StatusConflict, "the policy is read-only: it's synced from "+s.store.remote+"; change it there")
		return nil, false
	}

	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	cur := s.engine.Load().Policy()
	if match := r.Header.Get("If-Match"); match != "" && !etagMatches(match, cur.ETag()) {
		w.Header().Set("ETag", cur.ETag())
		writeError(w, http.StatusPreconditionFailed, "the policy changed since it was read; reload it and try again")
		return nil, false
	}

	next := cur.Clone()
	if err := change(next); err != nil {
		switch {
		case errors.Is(err, errNotFound):
			writeError(w, http.StatusNotFound, err.Error())
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return nil, false
	}
	next.Version = policy.Version

	if err := next.Validate(); err != nil {
		writePolicyError(w, err)
		return nil, false
	}
	if err := s.store.save(next); err != nil {
		s.logger.ErrorContext(r.Context(), "admin: saving policy", slog.Any("error", err))
		writeError(w, http.StatusInternalServerError, "saving the policy failed")
		return nil, false
	}
	if err := s.applyPolicy(next); err != nil {
		writePolicyError(w, err)
		return nil, false
	}

	s.logger.InfoContext(r.Context(), "admin: policy changed", slog.String("method", r.Method), slog.String("path", r.URL.Path))
	w.Header().Set("ETag", next.ETag())
	return next, true
}

func (s *Server) apiPutPolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if !decode(w, r, &p) {
		return
	}
	next, ok := s.updatePolicy(w, r, func(cur *policy.Policy) error {
		*cur = p
		return nil
	})
	if ok {
		writeJSON(w, http.StatusOK, next)
	}
}

func (s *Server) apiListProfiles(w http.ResponseWriter, r *http.Request) {
	p := s.engine.Load().Policy()
	w.Header().Set("ETag", p.ETag())
	writeJSON(w, http.StatusOK, api.Profiles{Profiles: p.Profiles})
}

func (s *Server) apiGetProfile(w http.ResponseWriter, r *http.Request) {
	p := s.engine.Load().Policy()
	pr := p.Profile(r.PathValue("id"))
	if pr == nil {
		writeError(w, http.StatusNotFound, "no profile "+strconv.Quote(r.PathValue("id")))
		return
	}
	w.Header().Set("ETag", p.ETag())
	writeJSON(w, http.StatusOK, pr)
}

func (s *Server) apiCreateProfile(w http.ResponseWriter, r *http.Request) {
	var pr policy.Profile
	if !decode(w, r, &pr) {
		return
	}
	next, ok := s.updatePolicy(w, r, func(p *policy.Policy) error {
		if p.Profile(pr.ID) != nil {
			return fmt.Errorf("profile %q already exists", pr.ID)
		}
		p.Profiles = append(p.Profiles, pr)
		return nil
	})
	if ok {
		w.Header().Set("Location", api.Prefix+"/profiles/"+pr.ID)
		writeJSON(w, http.StatusCreated, next.Profile(pr.ID))
	}
}

func (s *Server) apiDeleteProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, ok := s.updatePolicy(w, r, func(p *policy.Policy) error {
		i := slices.IndexFunc(p.Profiles, func(pr policy.Profile) bool { return pr.ID == id })
		if i < 0 {
			return fmt.Errorf("no profile %q: %w", id, errNotFound)
		}
		p.Profiles = slices.Delete(p.Profiles, i, i+1)
		return nil
	})
	if ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

// apiPatchProfile applies a JSON merge patch ([RFC 7396]) to a profile.
//
// [RFC 7396]: https://www.rfc-editor.org/rfc/rfc7396.html
func (s *Server) apiPatchProfile(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mt, _, _ := mime.ParseMediaType(ct); mt != api.MergePatchType && mt != "application/json" {
			w.Header().Set("Accept-Patch", api.MergePatchType)
			writeError(w, http.StatusUnsupportedMediaType, "send a JSON merge patch ("+api.MergePatchType+")")
			return
		}
	}

	patch, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAPIBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	if !jsontext.Value(patch).IsValid() {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	id := r.PathValue("id")
	next, ok := s.updatePolicy(w, r, func(p *policy.Policy) error {
		pr := p.Profile(id)
		if pr == nil {
			return fmt.Errorf("no profile %q: %w", id, errNotFound)
		}

		doc, err := json.Marshal(pr)
		if err != nil {
			return err
		}
		merged, err := mergePatch(doc, patch)
		if err != nil {
			return err
		}

		var patched policy.Profile
		if err := json.Unmarshal(merged, &patched, json.RejectUnknownMembers(true)); err != nil {
			return fmt.Errorf("invalid profile: %w", err)
		}
		if patched.ID != id {
			return errors.New("a profile's id can't be changed; create a new profile instead")
		}
		*pr = patched
		return nil
	})
	if ok {
		writeJSON(w, http.StatusOK, next.Profile(id))
	}
}

// mergePatch applies a JSON merge patch to doc ([RFC 7396, Section 2]):
// objects merge recursively, null removes a member, and anything else,
// including arrays, replaces the target.
//
// [RFC 7396, Section 2]: https://www.rfc-editor.org/rfc/rfc7396.html#section-2
func mergePatch(doc, patch []byte) ([]byte, error) {
	var target, p any
	if err := json.Unmarshal(doc, &target); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(patch, &p); err != nil {
		return nil, fmt.Errorf("invalid merge patch: %w", err)
	}
	return json.Marshal(mergeValue(target, p))
}

func mergeValue(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = make(map[string]any)
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
		} else {
			t[k] = mergeValue(t[k], v)
		}
	}
	return t
}

// apiDomain adds a domain to, or removes it from, a profile's allow list
// (allow) or deny list. Adding a domain to one list removes it from the
// other, so the latest decision wins.
func (s *Server) apiDomain(allow, add bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var domain string
		if add {
			var req api.DomainRequest
			if !decode(w, r, &req) {
				return
			}
			domain = req.Domain
		} else {
			domain = r.PathValue("domain")
		}

		normalized, ok := policy.NormalizeDomain(domain)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid domain "+strconv.Quote(domain))
			return
		}

		id := r.PathValue("id")
		next, ok := s.updatePolicy(w, r, func(p *policy.Policy) error {
			pr := p.Profile(id)
			if pr == nil {
				return fmt.Errorf("no profile %q: %w", id, errNotFound)
			}

			list, other := &pr.Allow, &pr.Deny
			if !allow {
				list, other = other, list
			}
			same := func(d string) bool { n, _ := policy.NormalizeDomain(d); return n == normalized }

			*list = slices.DeleteFunc(*list, same)
			if add {
				*list = append(*list, normalized)
				*other = slices.DeleteFunc(*other, same)
			}
			return nil
		})
		if ok {
			writeJSON(w, http.StatusOK, next.Profile(id))
		}
	}
}

// parseFilter reads query log filter parameters, writing any error.
func parseFilter(w http.ResponseWriter, r *http.Request) (querylog.Filter, bool) {
	f, err := querylog.ParseFilter(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return f, false
	}
	return f, true
}

func (s *Server) requireLog(w http.ResponseWriter) bool {
	if s.qlog == nil {
		writeError(w, http.StatusNotFound, "the query log is disabled")
		return false
	}
	return true
}

func (s *Server) apiLogs(w http.ResponseWriter, r *http.Request) {
	f, ok := parseFilter(w, r)
	if !ok || !s.requireLog(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.qlog.Query(f))
}

func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	f, ok := parseFilter(w, r)
	if !ok || !s.requireLog(w) {
		return
	}
	top := 10
	if v := r.URL.Query().Get("top"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			writeError(w, http.StatusBadRequest, "top must be between 1 and 100")
			return
		}
		top = n
	}
	writeJSON(w, http.StatusOK, s.qlog.Stats(f, top))
}

// apiStream streams new log entries as server-sent events.
func (s *Server) apiStream(w http.ResponseWriter, r *http.Request) {
	f, ok := parseFilter(w, r)
	if !ok || !s.requireLog(w) {
		return
	}

	// Subscribe before responding, so no entry logged after the client
	// sees the stream start is missed.
	entries := s.qlog.Subscribe(r.Context(), f)

	rc := http.NewResponseController(w)
	// Streams outlive the admin server's write timeout.
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, ": stream started\n\n")
	if err := rc.Flush(); err != nil {
		return
	}
	heartbeat := time.NewTicker(streamHeartbeat)
	defer heartbeat.Stop()

	var buf bytes.Buffer
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			_, _ = io.WriteString(w, ": ping\n\n")
		case e, ok := <-entries:
			if !ok {
				return
			}
			buf.Reset()
			buf.WriteString("event: entry\ndata: ")
			_ = json.MarshalWrite(&buf, e)
			buf.WriteString("\n\n")
			if _, err := w.Write(buf.Bytes()); err != nil {
				return
			}
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// apiExplain traces how a query would be answered, resolving it for real
// so answer checks run too, without logging or counting it.
func (s *Server) apiExplain(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()

	name := strings.TrimSpace(v.Get("name"))
	if _, ok := dns.IsDomainName(name); !ok || name == "" {
		writeError(w, http.StatusBadRequest, "name must be a domain name")
		return
	}

	qtype := dns.TypeA
	if t := strings.ToUpper(v.Get("type")); t != "" {
		var ok bool
		if qtype, ok = dns.StringToType[t]; !ok {
			writeError(w, http.StatusBadRequest, "unknown record type "+strconv.Quote(t))
			return
		}
	}

	var client netip.Addr
	if c := v.Get("client"); c != "" {
		var err error
		if client, err = netip.ParseAddr(c); err != nil {
			writeError(w, http.StatusBadRequest, "client must be an IP address")
			return
		}
	}

	profile := v.Get("profile")
	if profile != "" && s.engine.Load().Profile(profile) == nil {
		writeError(w, http.StatusNotFound, "no profile "+strconv.Quote(profile))
		return
	}

	query := new(dns.Msg).SetQuestion(dns.Fqdn(name), qtype)
	query.SetEdns0(dns.DefaultMsgSize, false)

	trace := &filter.Trace{}
	res, err := s.answer(r.Context(), request{transport: "explain", query: query, client: client, profile: profile, trace: trace})

	exp := api.Explanation{
		Name:     strings.TrimSuffix(strings.ToLower(name), "."),
		Type:     typeString(qtype),
		Profile:  res.profile,
		Device:   res.device,
		Decision: res.decision.Decision,
		Checks:   trace.Checks,
	}
	if exp.Checks == nil {
		exp.Checks = []api.Check{}
	}
	if client.IsValid() {
		exp.Client = client.String()
	}
	if exp.Decision.Action == "" {
		exp.Decision.Action = api.ActionAllow
	}

	switch {
	case err != nil:
		exp.Rcode = dns.RcodeToString[dns.RcodeServerFailure]
		exp.Decision.Detail = "resolving failed: " + err.Error()
	case res.resp != nil:
		exp.Rcode = dns.RcodeToString[res.resp.Rcode]
		exp.Answers = answers(res.resp)
		if res.cached {
			exp.Checks = append(exp.Checks, api.Check{Check: "resolved", Result: api.CheckPass, Detail: "answered from the cache"})
		} else if res.upstream != "" {
			exp.Checks = append(exp.Checks, api.Check{Check: "resolved", Result: api.CheckPass, Detail: "answered by " + res.upstream})
		}
	}

	writeJSON(w, http.StatusOK, exp)
}

// version returns the server's module version.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}
