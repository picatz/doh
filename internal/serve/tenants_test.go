package serve

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/querylog"
	"github.com/picatz/doh/internal/webauthn"
	"github.com/picatz/doh/internal/webauthn/webauthntest"
)

// tenantFixture is a server with an operator profile and a tenant, and a
// browser signed in as the tenant's admin.
type tenantFixture struct {
	s        *Server
	operator apiClient
	smith    *uiBrowser
}

func newTenantFixture(t *testing.T) *tenantFixture {
	t.Helper()
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{
		Tenants: []policy.Tenant{{ID: "smiths", Name: "The Smiths", Networks: []string{"192.168.10.0/24"}}},
		Profiles: []policy.Profile{
			{ID: "default"},
			{ID: "lab", Deny: []string{"secret.example"}},
			{ID: "smith-home", Tenant: "smiths"},
		},
	})
	adminURL := startAdmin(t, s)
	operator := apiClient{t, adminURL, token(t, dataDir, AdminTokenFile)}

	resp, body := operator.do(http.MethodPost, "/api/v1/signin-links", `{"tenant":"smiths"}`)
	var link api.SigninLink
	if err := json.Unmarshal(body, &link); resp.StatusCode != http.StatusCreated || err != nil {
		t.Fatalf("tenant link = %d %s", resp.StatusCode, body)
	}
	smith := newUIBrowser(t, adminURL)
	smith.signIn(link)

	return &tenantFixture{s: s, operator: operator, smith: smith}
}

func TestTenants_SeeOnlyTheirOwnProfiles(t *testing.T) {
	f := newTenantFixture(t)
	b := f.smith

	var profiles api.Profiles
	if status := b.do(http.MethodGet, "/api/v1/profiles", "", &profiles); status != http.StatusOK {
		t.Fatalf("list = %d", status)
	}
	if len(profiles.Profiles) != 1 || profiles.Profiles[0].ID != "smith-home" {
		t.Errorf("tenant sees %+v, want only its own profile", profiles.Profiles)
	}

	// Others' profiles look like they don't exist, whatever is tried.
	for _, tt := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/profiles/lab", ""},
		{http.MethodPatch, "/api/v1/profiles/lab", `{"deny":[]}`},
		{http.MethodDelete, "/api/v1/profiles/default", ""},
		{http.MethodPost, "/api/v1/profiles/lab/allow", `{"domain":"secret.example"}`},
		{http.MethodDelete, "/api/v1/profiles/lab/deny/secret.example", ""},
		{http.MethodGet, "/api/v1/profiles/lab/setup", ""},
		{http.MethodGet, "/api/v1/profiles/lab/apple.mobileconfig", ""},
		{http.MethodGet, "/api/v1/explain?name=secret.example&profile=lab", ""},
	} {
		if status := b.do(tt.method, tt.path, tt.body, nil); status != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", tt.method, tt.path, status)
		}
	}
	if p := f.s.engine.Load().Policy().Profile("lab"); len(p.Deny) != 1 {
		t.Error("a tenant changed the operator's profile")
	}

	// The operator's controls are off limits.
	for _, tt := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/policy", ""},
		{http.MethodPut, "/api/v1/policy", `{"profiles":[]}`},
		{http.MethodPost, "/api/v1/tenants", `{"id":"mine"}`},
		{http.MethodPatch, "/api/v1/tenants/smiths", `{"networks":["0.0.0.0/0"]}`},
		{http.MethodDelete, "/api/v1/tenants/smiths", ""},
	} {
		if status := b.do(tt.method, tt.path, tt.body, nil); status != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403", tt.method, tt.path, status)
		}
	}
}

func TestTenants_CreateWithinBounds(t *testing.T) {
	f := newTenantFixture(t)
	b := f.smith

	for _, tt := range []struct {
		desc, body string
		want       int
	}{
		{"own profile", `{"id":"smith-kids","clients":["192.168.10.64/26"]}`, http.StatusCreated},
		{"another tenant's", `{"id":"x","tenant":"jones"}`, http.StatusForbidden},
		{"the operator's", `{"id":"x","tenant":""}`, http.StatusCreated}, // empty means the caller's own
		{"capturing everyone", `{"id":"y","clients":["0.0.0.0/0"]}`, http.StatusBadRequest},
		{"someone else's network", `{"id":"y","devices":[{"name":"d","addrs":["10.0.0.5"]}]}`, http.StatusBadRequest},
		{"reading a file", `{"id":"y","lists":["/etc/shadow"]}`, http.StatusBadRequest},
		{"fetching a URL", `{"id":"y","lists":["https://169.254.169.254/latest"]}`, http.StatusBadRequest},
		{"a taken id", `{"id":"lab"}`, http.StatusBadRequest},
	} {
		if status := b.do(http.MethodPost, "/api/v1/profiles", tt.body, nil); status != tt.want {
			t.Errorf("%s: create = %d, want %d", tt.desc, status, tt.want)
		}
	}
	if p := f.s.engine.Load().Policy().Profile("x"); p == nil || p.Tenant != "smiths" {
		t.Errorf("profile created without a tenant = %+v, want it in the smiths tenant", p)
	}

	// A tenant can't move its profiles out of its tenant.
	if status := b.do(http.MethodPatch, "/api/v1/profiles/smith-kids", `{"tenant":null}`, nil); status != http.StatusBadRequest {
		t.Errorf("moving a profile to the operator = %d, want 400", status)
	}
}

func TestTenants_QueryLogIsTheirs(t *testing.T) {
	f := newTenantFixture(t)

	// One query from the tenant's profile, one from the operator's.
	ask := func(profile, name string) {
		q := new(dns.Msg).SetQuestion(name, dns.TypeA)
		if _, err := f.s.resolve(t.Context(), request{transport: "doh", query: q, client: netip.MustParseAddr("203.0.113.9"), profile: profile}); err != nil {
			t.Fatal(err)
		}
	}
	ask("smith-home", "family.example.")
	ask("lab", "secret.example.")

	var page querylog.Page
	if status := f.smith.do(http.MethodGet, "/api/v1/logs", "", &page); status != http.StatusOK {
		t.Fatalf("logs = %d", status)
	}
	if len(page.Entries) != 1 || page.Entries[0].Name != "family.example" || page.Entries[0].Tenant != "smiths" {
		t.Errorf("tenant's log = %+v, want only its own query", page.Entries)
	}
	// Asking for another profile's entries finds nothing.
	if f.smith.do(http.MethodGet, "/api/v1/logs?profile=lab", "", &page); len(page.Entries) != 0 {
		t.Errorf("tenant read the operator's log: %+v", page.Entries)
	}

	var stats querylog.Stats
	f.smith.do(http.MethodGet, "/api/v1/stats", "", &stats)
	if stats.Total != 1 {
		t.Errorf("tenant's stats count %d queries, want only its own", stats.Total)
	}

	// The operator sees everything.
	_, body := f.operator.do(http.MethodGet, "/api/v1/logs", "")
	if err := json.Unmarshal(body, &page); err != nil || len(page.Entries) != 2 {
		t.Errorf("operator's log = %s", body)
	}

	// Status tells tenants nothing about the server's traffic or setup.
	var status api.Status
	f.smith.do(http.MethodGet, "/api/v1/status", "", &status)
	if status.Tenant != "smiths" || len(status.Queries) != 0 || len(status.Lists) != 0 || len(status.Listeners) != 0 ||
		status.Policy.Profiles != 1 || status.QueryLog.Entries != 0 || status.QueryLog.Dir != "" {
		t.Errorf("tenant status = %+v", status)
	}

	// Explaining needs one of their profiles, so address matching can't
	// land on someone else's.
	if s := f.smith.do(http.MethodGet, "/api/v1/explain?name=x.example", "", nil); s != http.StatusBadRequest {
		t.Errorf("explain without a profile = %d, want 400", s)
	}
	if s := f.smith.do(http.MethodGet, "/api/v1/explain?name=x.example&profile=smith-home", "", nil); s != http.StatusOK {
		t.Errorf("explain with their profile = %d", s)
	}
}

func TestTenants_PeopleAndInvites(t *testing.T) {
	f := newTenantFixture(t)

	// Tenants invite only to their own tenant.
	if s := f.smith.do(http.MethodPost, "/api/v1/signin-links", `{"tenant":"jones"}`, nil); s != http.StatusForbidden {
		t.Errorf("inviting to another tenant = %d, want 403", s)
	}
	var link api.SigninLink
	if s := f.smith.do(http.MethodPost, "/api/v1/signin-links", `{"role":"reader"}`, &link); s != http.StatusCreated {
		t.Fatalf("inviting to their own tenant = %d", s)
	}
	if s, _ := f.operator.do(http.MethodPost, "/api/v1/signin-links", `{"tenant":"nobody"}`); s.StatusCode != http.StatusNotFound {
		t.Errorf("operator inviting to a missing tenant = %d, want 404", s.StatusCode)
	}

	// The invited reader signs in to the Smiths' tenant.
	reader := newUIBrowser(t, f.operator.base)
	reader.signIn(link)
	var profiles api.Profiles
	reader.do(http.MethodGet, "/api/v1/profiles", "", &profiles)
	if len(profiles.Profiles) != 1 || profiles.Profiles[0].ID != "smith-home" {
		t.Errorf("invited reader sees %+v", profiles.Profiles)
	}
	if s := reader.do(http.MethodPost, "/api/v1/profiles", `{"id":"z"}`, nil); s != http.StatusForbidden {
		t.Errorf("reader created a profile: %d", s)
	}

	// The operator's people aren't visible to, or removable by, the tenant.
	op := newUIBrowser(t, f.operator.base)
	op.signIn(newSigninLink(t, f.operator, "admin"))
	auth := &webauthntest.Authenticator{}
	var reg webauthn.RegistrationOptions
	if s := op.do(http.MethodPost, "/auth/passkey/register", `{"name":"Key","person":"Operator"}`, &reg); s != http.StatusOK {
		t.Fatalf("operator passkey begin = %d", s)
	}
	created, err := auth.Create(reg.Options.PublicKey, webauthntest.Response{Origin: op.base})
	if err != nil {
		t.Fatal(err)
	}
	if s := op.do(http.MethodPost, "/auth/passkey/register/"+reg.ID, string(created), nil); s != http.StatusCreated {
		t.Fatalf("operator passkey finish = %d", s)
	}

	var all api.People
	_, body := f.operator.do(http.MethodGet, "/api/v1/people", "")
	if err := json.Unmarshal(body, &all); err != nil || len(all.People) != 1 {
		t.Fatalf("operator's people = %s", body)
	}
	operatorID := all.People[0].ID

	var people api.People
	f.smith.do(http.MethodGet, "/api/v1/people", "", &people)
	if len(people.People) != 0 {
		t.Errorf("tenant sees %+v, want none of the operator's people", people.People)
	}
	if s := f.smith.do(http.MethodDelete, "/api/v1/people/"+operatorID, "", nil); s != http.StatusNotFound {
		t.Errorf("tenant removing the operator = %d, want 404", s)
	}
	if s := f.smith.do(http.MethodDelete, "/api/v1/people/"+operatorID+"/passkeys/x", "", nil); s != http.StatusNotFound {
		t.Errorf("tenant removing the operator's passkey = %d, want 404", s)
	}

	// The operator's passkey doesn't make the Smiths' links pending: each
	// tenant's rule is its own.
	var smithLink api.SigninLink
	f.smith.do(http.MethodPost, "/api/v1/signin-links", "", &smithLink)
	if smithLink.PasskeyRequired {
		t.Error("the operator's passkey made the tenant's links need one")
	}
}

func TestTenants_DeleteTenant(t *testing.T) {
	f := newTenantFixture(t)

	if resp, body := f.operator.do(http.MethodDelete, "/api/v1/tenants/smiths", ""); resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "still has 1 profiles") {
		t.Errorf("deleting a tenant with profiles = %d %s, want refused", resp.StatusCode, body)
	}
	if resp, _ := f.operator.do(http.MethodDelete, "/api/v1/profiles/smith-home", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatal("deleting the tenant's profile failed")
	}
	if resp, _ := f.operator.do(http.MethodDelete, "/api/v1/tenants/smiths", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deleting the tenant = %d", resp.StatusCode)
	}
	if f.s.engine.Load().Policy().Tenant("smiths") != nil {
		t.Error("tenant still exists")
	}
}

func TestTenants_OperatorManagesTenants(t *testing.T) {
	f := newTenantFixture(t)

	if resp, body := f.operator.do(http.MethodPost, "/api/v1/tenants", `{"id":"jones","networks":["192.168.10.128/25"]}`); resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "overlaps") {
		t.Errorf("overlapping tenant = %d %s, want refused", resp.StatusCode, body)
	}
	if resp, body := f.operator.do(http.MethodPost, "/api/v1/tenants", `{"id":"jones","name":"The Joneses","networks":["192.168.20.0/24"]}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create tenant = %d %s", resp.StatusCode, body)
	}
	if resp, body := f.operator.do(http.MethodPatch, "/api/v1/tenants/jones", `{"custom_lists":true}`); resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"custom_lists":true`) {
		t.Errorf("patch tenant = %d %s", resp.StatusCode, body)
	}
	if resp, _ := f.operator.do(http.MethodPatch, "/api/v1/tenants/jones", `{"id":"other"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("renaming a tenant's id = %d, want 400", resp.StatusCode)
	}

	var tenants api.Tenants
	f.smith.do(http.MethodGet, "/api/v1/tenants", "", &tenants)
	if len(tenants.Tenants) != 1 || tenants.Tenants[0].ID != "smiths" {
		t.Errorf("tenant lists %+v, want only itself", tenants.Tenants)
	}
}

func TestAdmin_DebugNeedsOperatorWhenPublished(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, nil, func(c *Config) {
		c.Admin.Origins = []string{"https://admin.dns.example.test"}
	})
	adminURL := startAdmin(t, s)

	for _, path := range []string{VarsPath, PprofPath, FlightRecorderPath} {
		if resp, _ := (apiClient{t, adminURL, ""}).do(http.MethodGet, path, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without credentials = %d, want 401", path, resp.StatusCode)
		}
	}
	if resp, _ := (apiClient{t, adminURL, token(t, dataDir, AdminTokenFile)}).do(http.MethodGet, VarsPath, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s as the operator = %d", VarsPath, resp.StatusCode)
	}
	// Metrics stay open, for scrapers.
	if resp, _ := (apiClient{t, adminURL, ""}).do(http.MethodGet, MetricsPath, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("GET %s = %d", MetricsPath, resp.StatusCode)
	}
}

func TestTenants_SetupGuidanceFitsWhoCanAct(t *testing.T) {
	f := newTenantFixture(t)

	var setup api.Setup
	if s := f.smith.do(http.MethodGet, "/api/v1/profiles/smith-home/setup", "", &setup); s != http.StatusOK {
		t.Fatalf("setup = %d", s)
	}
	for _, p := range setup.Platforms {
		for _, step := range p.Steps {
			if strings.Contains(step, "--") {
				t.Errorf("tenant's setup step %q tells them to change server flags", step)
			}
		}
	}
}
