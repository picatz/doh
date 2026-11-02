package serve

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
)

// ask sends s one query, as a client of profile and device would.
func ask(t *testing.T, s *Server, transport, profile, device, client string) {
	t.Helper()
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	req := request{transport: transport, query: q, client: netip.MustParseAddr(client), profile: profile, device: device}
	if _, err := s.resolve(t.Context(), req); err != nil {
		t.Fatal(err)
	}
}

func TestDevices_SeesASetUpDeviceConnect(t *testing.T) {
	up, _ := startZone(t, nil)
	s, dataDir := newPolicyServer(t, up, &policy.Policy{Profiles: []policy.Profile{
		{ID: "default"},
		// Logging off: the device is still seen.
		{ID: "kids", Logging: policy.Logging{Disabled: true}},
	}})
	adminURL := startAdmin(t, s)
	admin := apiClient{t, adminURL, token(t, dataDir, AdminTokenFile)}

	before := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	waiting := "/api/v1/devices?profile=kids&device=tablet&since=" + url.QueryEscape(before)

	var got api.SeenDevices
	if resp, body := admin.do(http.MethodGet, waiting, ""); resp.StatusCode != http.StatusOK || decodeJSON(t, body, &got) != nil || len(got.Devices) != 0 {
		t.Fatalf("before it connects = %d %s, want no devices", resp.StatusCode, body)
	}

	ask(t, s, "doh", "kids", "tablet", "192.0.2.10")
	ask(t, s, "doh", "kids", "", "192.0.2.11")
	ask(t, s, "udp", "", "", "192.0.2.12")

	_, body := admin.do(http.MethodGet, waiting, "")
	if decodeJSON(t, body, &got) != nil || len(got.Devices) != 1 {
		t.Fatalf("after it connects = %s, want the tablet", body)
	}
	if d := got.Devices[0]; d.Profile != "kids" || d.Device != "tablet" || d.Client != "192.0.2.10" || d.Transport != "doh" || d.First.IsZero() || d.Last.Before(d.First) {
		t.Errorf("device = %+v", d)
	}
	if got.Since.IsZero() {
		t.Error("the response doesn't say since when the server remembers")
	}

	// device= with no value asks for unnamed devices; no device param, any.
	for path, want := range map[string]int{
		"/api/v1/devices?profile=kids&device=": 1,
		"/api/v1/devices?profile=kids":         2,
		"/api/v1/devices":                      3,
		"/api/v1/devices?since=" + url.QueryEscape(time.Now().Add(time.Hour).UTC().Format(time.RFC3339)): 0,
		"/api/v1/devices?new=true&since=" + url.QueryEscape(before):                                      3,
	} {
		_, body := admin.do(http.MethodGet, path, "")
		if decodeJSON(t, body, &got) != nil || len(got.Devices) != want {
			t.Errorf("%s = %s, want %d devices", path, body, want)
		}
	}

	// A device seen before since isn't new, even if it's seen again.
	mid := time.Now().UTC().Add(time.Second).Format(time.RFC3339)
	time.Sleep(1100 * time.Millisecond)
	ask(t, s, "doh", "kids", "tablet", "192.0.2.10")
	_, body = admin.do(http.MethodGet, "/api/v1/devices?new=true&since="+url.QueryEscape(mid), "")
	if decodeJSON(t, body, &got) != nil || len(got.Devices) != 0 {
		t.Errorf("new since %s = %s, want none", mid, body)
	}
	_, body = admin.do(http.MethodGet, "/api/v1/devices?since="+url.QueryEscape(mid), "")
	if decodeJSON(t, body, &got) != nil || len(got.Devices) != 1 {
		t.Errorf("seen since %s = %s, want the tablet", mid, body)
	}

	// Readers may look; bad input is refused.
	reader := apiClient{t, adminURL, token(t, dataDir, ReaderTokenFile)}
	if resp, _ := reader.do(http.MethodGet, "/api/v1/devices", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("reader = %d, want 200", resp.StatusCode)
	}
	for _, path := range []string{"/api/v1/devices?since=yesterday", "/api/v1/devices?device=Not_A_Name", "/api/v1/devices?new=maybe"} {
		if resp, _ := admin.do(http.MethodGet, path, ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", path, resp.StatusCode)
		}
	}
	if resp, _ := admin.do(http.MethodGet, "/api/v1/devices?profile=nope", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown profile = %d, want 404", resp.StatusCode)
	}
}

func TestDevices_TenantsSeeOnlyTheirOwn(t *testing.T) {
	f := newTenantFixture(t)
	ask(t, f.s, "doh", "smith-home", "phone", "203.0.113.9")
	ask(t, f.s, "doh", "lab", "laptop", "203.0.113.10")
	ask(t, f.s, "udp", "default", "", "192.0.2.1")

	var got api.SeenDevices
	if status := f.smith.do(http.MethodGet, "/api/v1/devices", "", &got); status != http.StatusOK {
		t.Fatalf("tenant = %d", status)
	}
	if len(got.Devices) != 1 || got.Devices[0].Device != "phone" {
		t.Errorf("tenant sees %+v, want only its own phone", got.Devices)
	}
	// Others' profiles look like they don't exist.
	for _, path := range []string{"/api/v1/devices?profile=lab", "/api/v1/devices?profile=lab&device=laptop", "/api/v1/devices?profile=default"} {
		if status := f.smith.do(http.MethodGet, path, "", nil); status != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, status)
		}
	}

	// The operator sees everyone's.
	_, body := f.operator.do(http.MethodGet, "/api/v1/devices", "")
	if decodeJSON(t, body, &got) != nil || len(got.Devices) != 3 {
		t.Errorf("operator sees %s, want 3 devices", body)
	}

	// A profile deleted and made again under another tenant shows its new
	// owner nothing seen under the old one.
	if resp, body := f.operator.do(http.MethodDelete, "/api/v1/profiles/lab", ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete = %d %s", resp.StatusCode, body)
	}
	if resp, body := f.operator.do(http.MethodPost, "/api/v1/profiles", `{"id":"lab","tenant":"smiths"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, body)
	}
	if status := f.smith.do(http.MethodGet, "/api/v1/devices?profile=lab", "", &got); status != http.StatusOK || len(got.Devices) != 0 {
		t.Errorf("the new owner of lab = %d %+v, want none of the old owner's devices", status, got.Devices)
	}
}

func TestSeenDevices_Bounded(t *testing.T) {
	d := newSeenDevices(time.Now())
	start := time.Now()
	for i := range maxSeenDevices + 10 {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		d.observe("default", "", "", addr, "udp", start.Add(time.Duration(i)*time.Millisecond))
	}
	if n := len(d.devices); n > maxSeenDevices {
		t.Errorf("remembers %d devices, want at most %d", n, maxSeenDevices)
	}
	// The oldest went first.
	if _, ok := d.devices[seenKey{"default", "", netip.AddrFrom4([4]byte{10, 0, 0, 0})}]; ok {
		t.Error("the least recently seen device wasn't forgotten")
	}
	all := d.list(seenFilter{visible: func(string, string) bool { return true }})
	if len(all) != maxListedDevices || all[0].Last.Before(all[1].Last) {
		t.Errorf("listed %d, want %d, newest first", len(all), maxListedDevices)
	}
	var nilSeen *seenDevices
	nilSeen.observe("default", "", "", netip.Addr{}, "udp", start) // no panic
}

// decodeJSON decodes body into v, failing the test if it can't.
func decodeJSON(t *testing.T, body []byte, v any) error {
	t.Helper()
	err := json.Unmarshal(body, v)
	if err != nil {
		t.Errorf("decoding %s: %v", body, err)
	}
	return err
}
