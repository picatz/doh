package serve

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/api"
)

// ntfyCatcher is a stand-in ntfy server on loopback, which the operator
// may send alerts to over http.
type ntfyCatcher struct {
	*httptest.Server
	posts chan ntfyPost
}

type ntfyPost struct {
	title, body string
}

func newNtfyCatcher(t *testing.T) *ntfyCatcher {
	t.Helper()
	c := &ntfyCatcher{posts: make(chan ntfyPost, 16)}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.posts <- ntfyPost{r.Header.Get("Title"), string(b)}
	}))
	t.Cleanup(c.Close)
	return c
}

// next waits for the next post.
func (c *ntfyCatcher) next(t *testing.T) ntfyPost {
	t.Helper()
	select {
	case p := <-c.posts:
		return p
	case <-time.After(10 * time.Second):
		t.Fatal("no alert arrived")
		return ntfyPost{}
	}
}

func TestAlertsAPI(t *testing.T) {
	f := newTenantFixture(t)
	if resp, b := f.operator.do(http.MethodPost, "/api/v1/tenants", `{"id":"joneses","name":"The Joneses"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create tenant = %d %s", resp.StatusCode, b)
	}

	// Each sees its own alerts, with the kinds it can have.
	resp, b := f.operator.do(http.MethodGet, "/api/v1/alerts", "")
	var op api.Alerts
	if err := json.Unmarshal(b, &op); resp.StatusCode != http.StatusOK || err != nil || op.Tenant != "" || len(op.AvailableKinds) != 4 || !slices.Equal(op.Settings.Kinds, alerts.Kinds) || op.Destinations == nil {
		t.Fatalf("operator's alerts = %d %s", resp.StatusCode, b)
	}
	var smith api.Alerts
	if status := f.smith.do(http.MethodGet, "/api/v1/alerts", "", &smith); status != http.StatusOK || smith.Tenant != "smiths" || slices.Contains(smith.AvailableKinds, alerts.KindListFailed) {
		t.Fatalf("tenant's alerts = %d %+v", status, smith)
	}

	// A tenant adds a webhook, and sees its secret once.
	var added api.NewAlertDestination
	if status := f.smith.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"webhook","url":"https://hooks.example/doh","name":"Hub"}`, &added); status != http.StatusCreated {
		t.Fatalf("add destination = %d", status)
	}
	if !strings.HasPrefix(added.Secret, alerts.SecretPrefix) || added.Destination.Name != "Hub" || added.Destination.CreatedBy == "" {
		t.Fatalf("added %+v", added)
	}
	resp, b = f.operator.do(http.MethodGet, "/api/v1/alerts?tenant=smiths", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), added.Destination.ID) || strings.Contains(string(b), strings.TrimPrefix(added.Secret, alerts.SecretPrefix)) {
		t.Errorf("the operator's view of the tenant's alerts = %d %s", resp.StatusCode, b)
	}

	// Tenants can't make the server reach internal services.
	for _, u := range []string{"https://127.0.0.1/x", "https://10.0.0.1/x", "https://169.254.169.254/latest", "https://[::1]/x", "http://hooks.example/doh"} {
		if status := f.smith.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"ntfy","url":"`+u+`"}`, nil); status != http.StatusBadRequest {
			t.Errorf("tenant adding %s = %d, want 400", u, status)
		}
	}

	// Other tenants' alerts, and the operator's, don't exist for a tenant.
	ntfy := newNtfyCatcher(t)
	resp, b = f.operator.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"ntfy","url":"`+ntfy.URL+`/ops"}`)
	var opDest api.NewAlertDestination
	if err := json.Unmarshal(b, &opDest); resp.StatusCode != http.StatusCreated || err != nil || opDest.Secret != "" {
		t.Fatalf("operator adding a loopback ntfy destination = %d %s", resp.StatusCode, b)
	}
	for _, tt := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/alerts?tenant=joneses", ""},
		{http.MethodPatch, "/api/v1/alerts?tenant=joneses", `{"kinds":[]}`},
		{http.MethodPost, "/api/v1/alerts/destinations?tenant=joneses", `{"type":"ntfy","url":"https://ntfy.sh/x"}`},
		{http.MethodPost, "/api/v1/alerts/test?tenant=joneses", ""},
		{http.MethodDelete, "/api/v1/alerts/destinations/" + opDest.Destination.ID, ""},
		{http.MethodDelete, "/api/v1/alerts/destinations/" + opDest.Destination.ID + "?tenant=", ""},
	} {
		if status := f.smith.do(tt.method, tt.path, tt.body, nil); status != http.StatusNotFound {
			t.Errorf("tenant %s %s = %d, want 404", tt.method, tt.path, status)
		}
	}
	if _, dests, _ := f.s.alerts.Get(""); len(dests) != 1 {
		t.Errorf("a tenant removed the operator's destination: %+v", dests)
	}
	if resp, _ := f.operator.do(http.MethodGet, "/api/v1/alerts?tenant=nobody", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("operator naming no tenant = %d, want 404", resp.StatusCode)
	}

	// Readers and service accounts, even admins, can't touch alerts.
	reader := apiClient{t, f.operator.base, token(t, f.s.config.DataDir, ReaderTokenFile)}
	_, opBot := createAccount(t, f.operator, `{"name":"Bot","role":"admin"}`)
	_, smithBot := createAccount(t, f.operator, `{"name":"Smith bot","role":"admin","tenant":"smiths"}`)
	for name, c := range map[string]apiClient{"reader": reader, "operator's service account": opBot, "tenant's service account": smithBot} {
		for _, tt := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/v1/alerts", ""},
			{http.MethodPatch, "/api/v1/alerts", `{"kinds":[]}`},
			{http.MethodPost, "/api/v1/alerts/destinations", `{"type":"ntfy","url":"https://ntfy.sh/x"}`},
			{http.MethodDelete, "/api/v1/alerts/destinations/" + added.Destination.ID, ""},
			{http.MethodPost, "/api/v1/alerts/test", ""},
		} {
			if resp, b := c.do(tt.method, tt.path, tt.body); resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s %s = %d %s, want 403", name, tt.method, tt.path, resp.StatusCode, b)
			}
		}
	}

	// Settings are merge patched, and checked.
	var patched api.Alerts
	if status := f.smith.do(http.MethodPatch, "/api/v1/alerts", `{"kinds":["threat","new-device"],"quiet_hours":{"start":"22:00","end":"07:00"}}`, &patched); status != http.StatusOK {
		t.Fatalf("patch = %d", status)
	}
	if !slices.Equal(patched.Settings.Kinds, []alerts.Kind{alerts.KindThreat, alerts.KindNewDevice}) || patched.Settings.QuietHours == nil || patched.Settings.TimeZone != "UTC" {
		t.Errorf("patched = %+v", patched.Settings)
	}
	for _, body := range []string{`{"kinds":["list-failed"]}`, `{"kinds":["everything"]}`, `{"bogus":true}`, `{"time_zone":"Mars/Olympus"}`, `{"quiet_hours":{"start":"9pm","end":"07:00"}}`, `not json`} {
		if status := f.smith.do(http.MethodPatch, "/api/v1/alerts", body, nil); status != http.StatusBadRequest {
			t.Errorf("patch %s = %d, want 400", body, status)
		}
	}
	if resp, b := f.operator.do(http.MethodPatch, "/api/v1/alerts?tenant=smiths", `{"quiet_hours":null}`, "Content-Type", api.MergePatchType); resp.StatusCode != http.StatusOK || strings.Contains(string(b), "quiet_hours") || !strings.Contains(string(b), `"new-device"`) {
		t.Errorf("operator patching the tenant = %d %s", resp.StatusCode, b)
	}

	// A test reaches each destination, and reports how it went.
	resp, b = f.operator.do(http.MethodPost, "/api/v1/alerts/test", "")
	var test api.AlertTest
	if err := json.Unmarshal(b, &test); resp.StatusCode != http.StatusOK || err != nil || len(test.Deliveries) != 1 || !test.Deliveries[0].OK {
		t.Fatalf("test = %d %s", resp.StatusCode, b)
	}
	if p := ntfy.next(t); p.title != "Test alert from doh" {
		t.Errorf("test alert = %+v", p)
	}
	if status := f.smith.do(http.MethodPost, "/api/v1/alerts/test?tenant=", "", nil); status != http.StatusOK {
		t.Errorf("tenant test = %d", status) // reported as failed deliveries, not an error
	}

	// Removing a destination; a second time, it's gone.
	if status := f.smith.do(http.MethodDelete, "/api/v1/alerts/destinations/"+added.Destination.ID, "", nil); status != http.StatusNoContent {
		t.Errorf("remove = %d", status)
	}
	if status := f.smith.do(http.MethodDelete, "/api/v1/alerts/destinations/"+added.Destination.ID, "", nil); status != http.StatusNotFound {
		t.Errorf("remove again = %d, want 404", status)
	}
	if status := f.smith.do(http.MethodPost, "/api/v1/alerts/test", "", nil); status != http.StatusConflict {
		t.Errorf("test without destinations = %d, want 409", status)
	}
}

func TestAlerts_ThreatFromAQuery(t *testing.T) {
	f := newTenantFixture(t)
	for _, profile := range []string{"lab", "smith-home"} {
		if resp, b := f.operator.do(http.MethodPatch, "/api/v1/profiles/"+profile, `{"security":{"tunneling":true}}`, "Content-Type", api.MergePatchType); resp.StatusCode != http.StatusOK {
			t.Fatalf("enable tunneling = %d %s", resp.StatusCode, b)
		}
	}
	ntfy := newNtfyCatcher(t)
	if resp, b := f.operator.do(http.MethodPost, "/api/v1/alerts/destinations", `{"type":"ntfy","url":"`+ntfy.URL+`/ops"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("add destination = %d %s", resp.StatusCode, b)
	}

	// A tenant's query never reaches the operator's destinations.
	q := new(dns.Msg).SetQuestion("leak.smith.example.", dns.TypeNULL)
	if _, err := f.s.resolve(t.Context(), request{transport: "doh", query: q, client: netip.MustParseAddr("192.168.10.5"), profile: "smith-home"}); err != nil {
		t.Fatal(err)
	}

	q = new(dns.Msg).SetQuestion("data.tunnel.example.", dns.TypeNULL)
	resp, err := f.s.resolve(t.Context(), request{transport: "doh", query: q, client: netip.MustParseAddr("203.0.113.9"), profile: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
		t.Fatalf("tunneling wasn't blocked: %v", resp)
	}
	p := ntfy.next(t)
	if p.title != "Threat blocked on 203.0.113.9" || !strings.Contains(p.body, "data.tunnel.example") || !strings.Contains(p.body, "for lab") {
		t.Errorf("alert = %+v", p)
	}
	select {
	case extra := <-ntfy.posts:
		t.Errorf("unexpected alert: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}
