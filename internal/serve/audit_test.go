package serve

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/audit"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/jose/pkg/jwa"
)

// auditPage lists the audit trail as c, with query q.
func auditPage(t *testing.T, c apiClient, q string) audit.Page {
	t.Helper()
	resp, body := c.do(http.MethodGet, "/api/v1/audit"+q, "")
	var page audit.Page
	if err := json.Unmarshal(body, &page); resp.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("GET /audit%s = %d %s", q, resp.StatusCode, body)
	}
	return page
}

// browserAudit lists the audit trail as b.
func browserAudit(t *testing.T, b *uiBrowser, q string) audit.Page {
	t.Helper()
	var page audit.Page
	if status := b.do(http.MethodGet, "/api/v1/audit"+q, "", &page); status != http.StatusOK {
		t.Fatalf("GET /audit%s as a browser = %d", q, status)
	}
	return page
}

func actions(page audit.Page) []string {
	var out []string
	for _, e := range page.Events {
		out = append(out, e.Action)
	}
	return out
}

func find(page audit.Page, match func(audit.Event) bool) (audit.Event, bool) {
	i := slices.IndexFunc(page.Events, match)
	if i < 0 {
		return audit.Event{}, false
	}
	return page.Events[i], true
}

// "Who unblocked TikTok?" has an answer, for the household as well as the
// operator, even when it was the operator who did it.
func TestAudit_WhoUnblockedTikTok(t *testing.T) {
	f := newTenantFixture(t)

	if status := f.smith.do(http.MethodPatch, "/api/v1/profiles/smith-home", `{"services":["tiktok","fortnite"]}`, nil); status != http.StatusOK {
		t.Fatalf("blocking apps = %d", status)
	}
	if resp, body := f.operator.do(http.MethodPatch, "/api/v1/profiles/smith-home", `{"services":["fortnite"]}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("unblocking = %d %s", resp.StatusCode, body)
	}
	if status := f.smith.do(http.MethodPost, "/api/v1/profiles/smith-home/allow", `{"domain":"Example.COM"}`, nil); status != http.StatusOK {
		t.Fatalf("allowing = %d", status)
	}
	// The operator's own changes are the operator's.
	if resp, _ := f.operator.do(http.MethodPost, "/api/v1/profiles/lab/deny", `{"domain":"games.example"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("denying = %d", resp.StatusCode)
	}

	page := browserAudit(t, f.smith, "?action=profile")
	unblocked, ok := find(page, func(e audit.Event) bool { return e.Details["services.removed"] == "tiktok" })
	if !ok {
		t.Fatalf("the household can't see who unblocked TikTok: %+v", page.Events)
	}
	if unblocked.Actor.Kind != audit.ActorToken || unblocked.Actor.Name != "admin token" || unblocked.Tenant != "smiths" ||
		unblocked.Target != (audit.Target{Type: "profile", ID: "smith-home"}) || unblocked.Details["profile"] != "smith-home" ||
		unblocked.Summary != "Unblocked TikTok (tiktok) in profile smith-home" {
		t.Errorf("unblocking = %+v", unblocked)
	}
	blocked, ok := find(page, func(e audit.Event) bool { return e.Details["services.added"] != "" })
	if !ok || blocked.Actor.Kind != audit.ActorLink || blocked.Actor.Tenant != "smiths" || !strings.Contains(blocked.Summary, "Blocked TikTok (tiktok), Fortnite") {
		t.Errorf("blocking = %+v", blocked)
	}
	allowed, ok := find(page, func(e audit.Event) bool { return e.Details["allow.added"] == "example.com" })
	if !ok || !strings.HasPrefix(allowed.Summary, "Allowed example.com") {
		t.Errorf("allowing = %+v", allowed)
	}
	if _, ok := find(page, func(e audit.Event) bool { return e.Target.ID == "lab" }); ok {
		t.Error("the household sees the operator's own profile's changes")
	}
	// Newest first.
	if page.Events[0].Details["allow.added"] != "example.com" {
		t.Errorf("first event = %+v, want the newest", page.Events[0])
	}

	// The operator sees everyone's, and can narrow to a tenant, an actor,
	// or an action.
	all := auditPage(t, f.operator, "")
	if _, ok := find(all, func(e audit.Event) bool { return e.Target.ID == "lab" && e.Details["deny.added"] == "games.example" }); !ok {
		t.Errorf("the operator doesn't see its own change: %v", actions(all))
	}
	if _, ok := find(all, func(e audit.Event) bool { return e.Action == "signin_link.created" && e.Tenant == "smiths" }); !ok {
		t.Errorf("the invitation isn't recorded: %v", actions(all))
	}
	for _, e := range auditPage(t, f.operator, "?tenant=smiths").Events {
		if e.Tenant != "smiths" {
			t.Errorf("?tenant=smiths has %+v", e)
		}
	}
	for _, e := range auditPage(t, f.operator, "?actor=admin&action=profile.updated").Events {
		if e.Actor.ID != "admin" || e.Action != "profile.updated" {
			t.Errorf("?actor=admin&action=profile.updated has %+v", e)
		}
	}
}

// Tenants see only their own trail, whatever they ask for.
func TestAudit_TenantScoping(t *testing.T) {
	f := newTenantFixture(t)
	// A second tenant, with its own change.
	if resp, body := f.operator.do(http.MethodPost, "/api/v1/tenants", `{"id":"joneses"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("tenant = %d %s", resp.StatusCode, body)
	}
	if resp, body := f.operator.do(http.MethodPost, "/api/v1/profiles", `{"id":"jones-home","tenant":"joneses"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("profile = %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.operator.do(http.MethodPost, "/api/v1/profiles/lab/allow", `{"domain":"ops.example"}`); resp.StatusCode != http.StatusOK {
		t.Fatal("operator change failed")
	}

	for _, q := range []string{"", "?tenant=joneses", "?tenant=", "?actor=admin", "?action=tenant"} {
		page := browserAudit(t, f.smith, q)
		for _, e := range page.Events {
			if e.Tenant != "smiths" {
				t.Errorf("%q: the Smiths see %+v", q, e)
			}
		}
		if q == "?tenant=joneses" || q == "?tenant=" {
			if len(page.Events) != 0 {
				t.Errorf("%q: the Smiths see %d events of others", q, len(page.Events))
			}
		}
	}
	// A page token made for the operator's trail continues only within
	// the Smiths' own.
	page := auditPage(t, f.operator, "?limit=1")
	if page.NextPageToken == "" {
		t.Fatal("no next page")
	}
	for _, e := range browserAudit(t, f.smith, "?page_token="+page.NextPageToken).Events {
		if e.Tenant != "smiths" {
			t.Errorf("with the operator's page token, the Smiths see %+v", e)
		}
	}

	if got := auditPage(t, f.operator, "?tenant=joneses"); len(got.Events) == 0 || got.Events[0].Tenant != "joneses" {
		t.Errorf("the operator can't see the Joneses': %+v", got.Events)
	}
}

func TestAudit_NeedsAnAdmin(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}})
	base := startAdmin(t, s)
	operator := apiClient{t, base, token(t, dataDir, AdminTokenFile)}
	reader := apiClient{t, base, token(t, dataDir, ReaderTokenFile)}
	nobody := apiClient{t, base, "doh_admin_forged"}

	if resp, _ := reader.do(http.MethodGet, "/api/v1/audit", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader = %d, want 403", resp.StatusCode)
	}
	if resp, _ := nobody.do(http.MethodGet, "/api/v1/audit", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged token = %d, want 401", resp.StatusCode)
	}
	_, readerSA := createAccount(t, operator, `{"name":"Dashboards"}`)
	if resp, _ := readerSA.do(http.MethodGet, "/api/v1/audit", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reader service account = %d, want 403", resp.StatusCode)
	}
	_, adminSA := createAccount(t, operator, `{"name":"SIEM","role":"admin"}`)
	if resp, body := adminSA.do(http.MethodGet, "/api/v1/audit?action=service_account", ""); resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "SIEM") {
		t.Errorf("admin service account = %d %s", resp.StatusCode, body)
	}
	for _, q := range []string{"?limit=0", "?limit=1001", "?before=yesterday", "?page_token=forged", "?actor=" + strings.Repeat("a", 300)} {
		if resp, _ := operator.do(http.MethodGet, "/api/v1/audit"+q, ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, resp.StatusCode)
		}
	}
}

// Secrets made or used by a change never reach the audit trail.
func TestAudit_NeverRecordsSecrets(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{{ID: "default"}}})
	base := startAdmin(t, s)
	operator := apiClient{t, base, token(t, dataDir, AdminTokenFile)}

	var secrets []string
	a, keyClient := createAccount(t, operator, `{"name":"Backups","role":"admin"}`)
	secrets = append(secrets, keyClient.token, operator.token)
	keyID := strings.Split(keyClient.token, "_")[2] // doh_sa_<key ID>_<secret>
	resp, body := operator.do(http.MethodPost, "/api/v1/service-accounts/"+a.ID+"/keys/"+keyID+"/rotate", `{}`)
	var rotated struct{ Secret string }
	if err := json.Unmarshal(body, &rotated); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("rotate = %d %s", resp.StatusCode, body)
	}
	secrets = append(secrets, rotated.Secret)

	resp, body = operator.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"ntfy","url":"https://alice:hunter2@ntfy.example/topic-7f3a"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("destination = %d %s", resp.StatusCode, body)
	}
	resp, body = operator.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"webhook","url":"https://hooks.example/doh"}`)
	var hook struct{ Secret string }
	if err := json.Unmarshal(body, &hook); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("webhook = %d %s", resp.StatusCode, body)
	}
	secrets = append(secrets, hook.Secret, strings.TrimPrefix(hook.Secret, "whsec_"), "hunter2", "topic-7f3a")

	link := newSigninLink(t, operator, "admin")
	_, code, _ := strings.Cut(link.URL, "#signin=")
	secrets = append(secrets, code)
	resp, body = operator.do(http.MethodPost, "/api/v1/profiles/default/setup-links", "")
	if resp.StatusCode/100 == 2 {
		var l struct{ URL string }
		_ = json.Unmarshal(body, &l)
		secrets = append(secrets, l.URL[strings.LastIndex(l.URL, "/")+1:])
	}

	resp, body = operator.do(http.MethodGet, "/api/v1/audit", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(string(body), secret) {
			t.Errorf("the audit trail holds a secret, %q", secret)
		}
	}
	for _, want := range []string{"service_account.key.rotated", "alerts.destination.added", "ntfy.example", "signin_link.created"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the audit trail lacks %q: %s", want, body)
		}
	}
}

// What changes the policy is described per profile and tenant.
func TestPolicyChanges(t *testing.T) {
	before := &policy.Policy{
		Tenants:  []policy.Tenant{{ID: "smiths"}, {ID: "gone"}},
		Profiles: []policy.Profile{{ID: "kids", Tenant: "smiths", Services: []string{"tiktok"}}, {ID: "old"}, {ID: "same"}},
	}
	after := &policy.Policy{
		Tenants:  []policy.Tenant{{ID: "smiths", Name: "The Smiths"}, {ID: "new"}},
		Profiles: []policy.Profile{{ID: "kids", Tenant: "new", Security: policy.Security{Bypass: true}}, {ID: "same"}, {ID: "fresh", Tenant: "smiths"}},
	}
	var got []string
	for _, c := range policyChanges(before, after) {
		got = append(got, c.action+" "+c.target.ID+" for "+c.tenant)
	}
	want := []string{
		"profile.updated kids for smiths", // moved: both tenants see it
		"profile.updated kids for new",
		"profile.created fresh for smiths",
		"profile.deleted old for ",
		"tenant.updated smiths for smiths",
		"tenant.created new for new",
		"tenant.deleted gone for gone",
	}
	if !slices.Equal(got, want) {
		t.Errorf("changes:\n got %q\nwant %q", got, want)
	}
	c := policyChanges(before, after)[0]
	if c.details["services.removed"] != "tiktok" || c.details["security.bypass"] != "true" || c.details["tenant"] != "new" {
		t.Errorf("details = %v", c.details)
	}
	if !strings.Contains(c.summary, "Unblocked TikTok (tiktok)") || !strings.Contains(c.summary, "changed security.bypass, tenant") {
		t.Errorf("summary = %q", c.summary)
	}
}

// Sign-ins, setup links, DPoP proofs, and the audit trail survive a
// restart: they're in the state database.
func TestState_SurvivesRestart(t *testing.T) {
	up, _ := startZone(t, nil)
	dataDir := t.TempDir()
	writePolicy(t, dataDir, &policy.Policy{Profiles: []policy.Profile{{ID: "kids"}}})
	log := new(syncBuffer)
	config := Config{
		Plaintext: true,
		Hostname:  "dns.example.com",
		Upstreams: []string{up},
		DataDir:   dataDir,
		Blocklist: BlocklistConfig{CacheDir: t.TempDir()},
		RDAP:      RDAPConfig{BootstrapURL: "http://127.0.0.1:1/unreachable"},
	}

	// run serves the admin listener at addr ("" for any port), until
	// stopped.
	run := func(addr string) (base string, public http.Handler, stop func()) {
		t.Helper()
		s, err := New(config, slog.New(slog.NewTextHandler(io.MultiWriter(log, t.Output()), nil)))
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", cmp.Or(addr, "127.0.0.1:0"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- s.ServeAdmin(ctx, ln) }()
		var once bool
		stop = func() {
			if once {
				return
			}
			once = true
			cancel()
			<-done
			s.Close()
		}
		t.Cleanup(stop)
		// Setup pages are on the public listener.
		return "http://" + ln.Addr().String(), s.Handler(), stop
	}

	base, _, stop := run("")
	operator := apiClient{t, base, token(t, dataDir, AdminTokenFile)}
	browser := newUIBrowser(t, base)
	browser.signIn(newSigninLink(t, operator, "admin"))
	resp, body := operator.do(http.MethodPost, "/api/v1/profiles/kids/setup-links?device=tablet", "")
	var link struct{ URL string }
	if err := json.Unmarshal(body, &link); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("setup link = %d %s", resp.StatusCode, body)
	}
	p := newProver(t, jwa.ES256)
	_, bound := boundKey(t, operator, p)
	proof := p.proof(t, http.MethodGet, base+"/api/v1/status", bound.token)
	if resp, body := dpopRequest(t, bound, http.MethodGet, "/api/v1/status", "DPoP", proof); resp.StatusCode != http.StatusOK {
		t.Fatalf("first use of a proof = %d %s", resp.StatusCode, body)
	}
	if status := browser.do(http.MethodPatch, "/api/v1/profiles/kids", `{"services":["tiktok"]}`, nil); status != http.StatusOK {
		t.Fatalf("change = %d", status)
	}
	stop()

	// The same address, so the proof's URL still matches.
	base, public, _ := run(strings.TrimPrefix(base, "http://"))

	if status := browser.do(http.MethodGet, "/api/v1/status", "", nil); status != http.StatusOK {
		t.Errorf("after a restart, the browser's session = %d, want still signed in", status)
	}
	rec := httptest.NewRecorder()
	u := link.URL[strings.Index(link.URL, setupPath):]
	public.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "tablet") {
		t.Errorf("after a restart, the setup link = %d", rec.Code)
	}
	if resp, body := dpopRequest(t, bound, http.MethodGet, "/api/v1/status", "DPoP", proof); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(log.String(), "replayed") {
		t.Errorf("after a restart, a replayed proof = %d %s, want refused as a replay", resp.StatusCode, body)
	}
	page := auditPage(t, operator, "?action=profile.updated")
	if len(page.Events) != 1 || page.Events[0].Details["services.added"] != "tiktok" || page.Events[0].Actor.Kind != audit.ActorLink {
		t.Errorf("after a restart, the audit trail = %+v", page.Events)
	}
	_ = base
}
