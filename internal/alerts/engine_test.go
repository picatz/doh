package alerts

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/querylog"
)

// sentAlert is an alert a test engine sent.
type sentAlert struct {
	scope, dest string
	alert       Alert
}

// recorder records what a test engine sends, instead of sending it.
type recorder struct {
	mu   sync.Mutex
	sent []sentAlert
}

func (r *recorder) send(_ context.Context, scope string, d destination, a Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, sentAlert{scope, d.ID, a})
	return nil
}

// take returns what was sent since it was last called.
func (r *recorder) take() []sentAlert {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.sent
	r.sent = nil
	return out
}

// titles returns the titles of what was sent since take was last called.
func (r *recorder) titles() []string {
	var out []string
	for _, s := range r.take() {
		out = append(out, s.alert.Title)
	}
	return out
}

// startEngine starts an engine that records what it sends. Call it in a
// synctest bubble, and close the engine before the bubble ends.
func startEngine(t *testing.T, opts Options) (*Engine, *recorder) {
	t.Helper()
	if opts.ProfileName == nil {
		opts.ProfileName = func(id string) string {
			if id == "kids" {
				return "Kids' tablets"
			}
			return ""
		}
	}
	if opts.Canary == nil {
		opts.Canary = func(name string) bool { return name == "use-application-dns.net" || name == "mask.icloud.com" }
	}
	e, err := newEngine(opts)
	if err != nil {
		t.Fatal(err)
	}
	rec := new(recorder)
	e.send = rec.send
	e.start()
	return e, rec
}

// addDestination adds an ntfy destination to scope.
func addDestination(t *testing.T, e *Engine, scope string) Destination {
	t.Helper()
	d, _, err := e.AddDestination(context.Background(), scope, NewDestination{Type: Ntfy, URL: "https://ntfy.example/" + scope + "-alerts"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// only turns on only kinds for scope.
func only(t *testing.T, e *Engine, scope string, kinds ...Kind) {
	t.Helper()
	if _, err := e.SetSettings(scope, Settings{Kinds: kinds}); err != nil {
		t.Fatal(err)
	}
}

// threatEntry is a query blocked by the threat intelligence list.
func threatEntry(tenant, profile, device, name string) querylog.Entry {
	return querylog.Entry{
		Time: time.Now(), Tenant: tenant, Profile: profile, Device: device, Client: "192.168.1.20",
		Name: name, Type: "A", Status: querylog.StatusBlocked, Reason: reasonList, Rule: name,
		Source: blocklist.ThreatIntelPreset, Detail: "blocked by " + blocklist.ThreatIntelPreset,
	}
}

func TestEngine_Threats(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, rec := startEngine(t, Options{Origin: "https://admin.dns.example"})
		defer e.Close()
		addDestination(t, e, "")
		only(t, e, "", KindThreat)

		e.Observe(threatEntry("", "kids", "kids-ipad", "evil-c2.example"))
		synctest.Wait()
		sent := rec.take()
		if len(sent) != 1 {
			t.Fatalf("sent %d alerts, want 1", len(sent))
		}
		a := sent[0].alert
		if a.Title != "Threat blocked on kids-ipad" || a.Kind != KindThreat || a.Type != "alert.threat" || a.Scope != "" || !strings.HasPrefix(a.ID, "msg_") {
			t.Errorf("alert = %+v", a)
		}
		for _, want := range []string{"evil-c2.example", "command-and-control", "(Threat intelligence list)", "for Kids' tablets.", "Nothing reached it.", "See it: https://admin.dns.example/#/logs?"} {
			if !strings.Contains(a.Body, want) {
				t.Errorf("body lacks %q: %s", want, a.Body)
			}
		}
		if d := a.Details; d.Name != "evil-c2.example" || d.List != blocklist.ThreatIntelPreset || d.Device != "kids-ipad" || d.Profile != "kids" || !strings.Contains(d.Link, "q=evil-c2.example") {
			t.Errorf("details = %+v", d)
		}

		// What isn't a threat isn't alerted on: ads, canaries, schedules.
		for _, en := range []querylog.Entry{
			{Profile: "kids", Device: "kids-ipad", Name: "ads.example", Status: querylog.StatusBlocked, Reason: reasonList, Source: "hagezi-normal"},
			{Profile: "kids", Device: "kids-ipad", Name: "use-application-dns.net", Status: querylog.StatusBlocked, Reason: reasonBypass},
			{Profile: "kids", Device: "kids-ipad", Name: "mask.icloud.com", Status: querylog.StatusBlocked, Reason: reasonBypass},
			{Profile: "kids", Device: "kids-ipad", Name: "tiktok.com", Status: querylog.StatusBlocked, Reason: "schedule", Source: "threat-intel"},
			{Profile: "kids", Device: "kids-ipad", Name: "evil.example", Status: querylog.StatusAllowed},
			{Name: "evil.example", Status: querylog.StatusBlocked, Reason: reasonList, Source: blocklist.ThreatIntelPreset}, // refused: no profile
		} {
			e.Observe(en)
		}
		synctest.Wait()
		if got := rec.titles(); len(got) != 0 {
			t.Errorf("non-threats alerted: %q", got)
		}

		// A bypass service is a threat, worded as what it is.
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "kids", Device: "kids-ipad", Name: "dns.google", Rule: "dns.google", Status: querylog.StatusBlocked, Reason: reasonBypass, Detail: "public encrypted DNS service"})
		synctest.Wait()
		if got := rec.titles(); !slices.Equal(got, []string{"Bypass blocked on kids-ipad"}) {
			t.Errorf("bypass alerts = %q", got)
		}
	})
}

func TestEngine_CoalescesAndSummarizesBursts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, rec := startEngine(t, Options{})
		defer e.Close()
		addDestination(t, e, "")
		only(t, e, "", KindThreat)

		// The same threat on the same device is sent once an hour.
		for range 5 {
			e.Observe(threatEntry("", "kids", "kids-ipad", "evil.example"))
		}
		synctest.Wait()
		if got := rec.titles(); len(got) != 1 {
			t.Fatalf("repeats sent %d alerts, want 1", len(got))
		}

		// Different threats on it are sent up to the burst limit, then
		// held; another device's are its own.
		for i := range 14 {
			e.Observe(threatEntry("", "kids", "kids-ipad", fmt.Sprintf("evil%d.example", i)))
		}
		e.Observe(threatEntry("", "kids", "living-room-tv", "evil.example"))
		synctest.Wait()
		got := rec.titles()
		slices.Sort(got) // two workers deliver
		if want := []string{"Threat blocked on kids-ipad", "Threat blocked on kids-ipad", "Threat blocked on living-room-tv"}; !slices.Equal(got, want) {
			t.Fatalf("burst sent %q, want %q", got, want)
		}

		// When the hour is up, what was held is summarized, once.
		time.Sleep(CoalesceWindow + tickInterval)
		synctest.Wait()
		sent := rec.take()
		if len(sent) != 1 {
			t.Fatalf("summaries = %d, want 1", len(sent))
		}
		a := sent[0].alert
		if a.Title != "12 more threats blocked on kids-ipad in the last hour" || a.Details.Count != 12 || len(a.Details.Names) != maxBurstNames || a.Kind != KindThreat {
			t.Errorf("summary = %+v", a)
		}
		if !strings.Contains(a.Body, "including evil2.example, evil3.example, and evil4.example") {
			t.Errorf("summary body = %s", a.Body)
		}

		// After the hour, the same threat is news again.
		e.Observe(threatEntry("", "kids", "kids-ipad", "evil.example"))
		synctest.Wait()
		if got := rec.titles(); len(got) != 1 {
			t.Errorf("after an hour, sent %q", got)
		}
		time.Sleep(2 * CoalesceWindow)
		synctest.Wait()
		if got := rec.titles(); len(got) != 0 {
			t.Errorf("a burst with nothing held summarized: %q", got)
		}
	})
}

func TestEngine_NewDevices(t *testing.T) {
	path := t.TempDir() + "/alerts.json"
	synctest.Test(t, func(t *testing.T) {
		mem := NewMemory() // durable across the restart below
		e, rec := startEngine(t, Options{Path: path, Memory: mem})
		addDestination(t, e, "")
		only(t, e, "", KindNewDevice)

		// Devices seen in the first hour are learned silently.
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "home", Client: "192.168.1.10", Hostname: "laptop", Status: querylog.StatusAllowed})
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "kids", Device: "kids-ipad", Client: "192.168.1.11", Status: querylog.StatusAllowed})
		synctest.Wait()
		time.Sleep(LearningPeriod)
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "home", Client: "192.168.1.10", Status: querylog.StatusAllowed})
		synctest.Wait()
		if got := rec.titles(); len(got) != 0 {
			t.Fatalf("learning period alerted: %q", got)
		}

		// After it, a new device is news, once.
		for range 3 {
			e.Observe(querylog.Entry{Time: time.Now(), Profile: "home", Client: "192.168.1.50", Hostname: "living-room-tv", Status: querylog.StatusAllowed})
		}
		synctest.Wait()
		sent := rec.take()
		if len(sent) != 1 || sent[0].alert.Title != "New device: living-room-tv" || !strings.Contains(sent[0].alert.Body, "Its address is 192.168.1.50.") {
			t.Fatalf("new device alerts = %+v", sent)
		}

		// A configured device name is its own device, whatever its address.
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "kids", Device: "kids-phone", Client: "192.168.1.10", Status: querylog.StatusAllowed})
		synctest.Wait()
		if got := rec.titles(); !slices.Equal(got, []string{"New device: kids-phone"}) {
			t.Errorf("named device alerts = %q", got)
		}
		if err := e.Close(); err != nil {
			t.Fatal(err)
		}

		// The devices seen survive a restart.
		e, rec = startEngine(t, Options{Path: path, Memory: mem})
		defer e.Close()
		for _, en := range []querylog.Entry{
			{Time: time.Now(), Profile: "home", Client: "192.168.1.10"},
			{Time: time.Now(), Profile: "home", Client: "192.168.1.50"},
			{Time: time.Now(), Profile: "kids", Device: "kids-ipad"},
			{Time: time.Now(), Profile: "home", Client: "192.168.1.99"},
		} {
			e.Observe(en)
		}
		synctest.Wait()
		if got := rec.titles(); !slices.Equal(got, []string{"New device: 192.168.1.99"}) {
			t.Errorf("after a restart, alerts = %q, want only the new device", got)
		}
	})
}

func TestEngine_FailingThresholds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, rec := startEngine(t, Options{})
		defer e.Close()
		addDestination(t, e, "")
		addDestination(t, e, "smiths")
		only(t, e, "", KindFailing)
		only(t, e, "smiths", KindFailing)

		fail := func(tenant string, n int) {
			for range n {
				e.Observe(querylog.Entry{Time: time.Now(), Tenant: tenant, Profile: "p", Client: "192.168.1.1", Status: querylog.StatusError, Rule: "upstream 192.0.2.53: i/o timeout"})
			}
		}
		ok := func(tenant string, n int) {
			for range n {
				e.Observe(querylog.Entry{Time: time.Now(), Tenant: tenant, Profile: "p", Client: "192.168.1.1", Status: querylog.StatusAllowed})
			}
		}

		// 19 errors aren't enough, however high the rate.
		fail("smiths", 19)
		synctest.Wait()
		if got := rec.take(); len(got) != 0 {
			t.Fatalf("19 errors alerted: %+v", got)
		}

		// The 20th is, for the tenant, and for the operator, whose window
		// covers the whole server.
		fail("smiths", 1)
		synctest.Wait()
		sent := rec.take()
		byScope := map[string]Alert{}
		for _, s := range sent {
			byScope[s.scope] = s.alert
		}
		if len(sent) != 2 || byScope["smiths"].Title != "Lookups are failing" || byScope[""].Title != "Lookups are failing" {
			t.Fatalf("failing alerts = %+v", sent)
		}
		if strings.Contains(byScope["smiths"].Body, "192.0.2.53") || byScope["smiths"].Details.Error != "" {
			t.Errorf("a tenant was told the server's error: %s", byScope["smiths"].Body)
		}
		if !strings.Contains(byScope[""].Body, "upstream 192.0.2.53: i/o timeout") || !strings.Contains(byScope[""].Body, "20 of 20 lookups (100%)") {
			t.Errorf("operator's alert = %s", byScope[""].Body)
		}

		// Later, below 10% isn't failing, even with enough errors.
		time.Sleep(CoalesceWindow + FailingWindow)
		ok("", 300)
		fail("", 25) // 25 of 325: 7.7%
		synctest.Wait()
		if got := rec.take(); len(got) != 0 {
			t.Fatalf("7.7%% failing alerted: %+v", got)
		}
		fail("", 10) // 35 of 335: 10.4%
		synctest.Wait()
		if got := rec.titles(); !slices.Equal(got, []string{"Lookups are failing"}) {
			t.Errorf("10%% failing alerts = %q", got)
		}

		// Errors spread beyond the window don't add up.
		time.Sleep(CoalesceWindow)
		for range 4 {
			fail("", 10)
			time.Sleep(FailingWindow + time.Minute)
		}
		synctest.Wait()
		if got := rec.titles(); len(got) != 0 {
			t.Errorf("errors outside the window alerted: %q", got)
		}
	})
}

func TestSettings_QuietAcrossMidnight(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no time zone database:", err)
	}
	s, err := Settings{QuietHours: &QuietHours{Start: "22:00", End: "07:00"}, TimeZone: "America/New_York"}.normalize("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 11, 2, 21, 59, 0, 0, ny), false},
		{time.Date(2026, 11, 2, 22, 0, 0, 0, ny), true},
		{time.Date(2026, 11, 2, 23, 30, 0, 0, ny), true},
		{time.Date(2026, 11, 3, 0, 0, 0, 0, ny), true},
		{time.Date(2026, 11, 3, 6, 59, 0, 0, ny), true},
		{time.Date(2026, 11, 3, 7, 0, 0, 0, ny), false},
		{time.Date(2026, 11, 3, 12, 0, 0, 0, ny), false},
		// The same instants in UTC are judged in New York's time.
		{time.Date(2026, 11, 3, 3, 30, 0, 0, time.UTC), true},  // 22:30 EST
		{time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC), false}, // 08:00 EST
	} {
		if got := s.Quiet(tt.at); got != tt.want {
			t.Errorf("Quiet(%v) = %v, want %v", tt.at, got, tt.want)
		}
	}

	day := Settings{QuietHours: &QuietHours{Start: "13:00", End: "14:00"}}
	if !day.Quiet(time.Date(2026, 1, 1, 13, 30, 0, 0, time.UTC)) || day.Quiet(time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC)) {
		t.Error("quiet hours within a day")
	}

	for _, bad := range []Settings{
		{QuietHours: &QuietHours{Start: "22:00", End: "22:00"}},
		{QuietHours: &QuietHours{Start: "25:00", End: "07:00"}},
		{QuietHours: &QuietHours{Start: "10pm", End: "07:00"}},
		{TimeZone: "Mars/Olympus"},
		{TimeZone: "Local"},
		{Kinds: []Kind{"everything"}},
	} {
		if _, err := bad.normalize(""); err == nil {
			t.Errorf("normalize(%+v) accepted", bad)
		}
	}
}

func TestEngine_QuietHours(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// The bubble starts at midnight UTC: 19:00 in New York.
		e, rec := startEngine(t, Options{})
		defer e.Close()
		addDestination(t, e, "")
		if _, err := e.SetSettings("", Settings{Kinds: Kinds, QuietHours: &QuietHours{Start: "22:00", End: "07:00"}, TimeZone: "America/New_York"}); err != nil {
			t.Fatal(err)
		}
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "home", Client: "192.168.1.1"}) // starts learning
		time.Sleep(3*time.Hour + time.Minute)                                               // 22:01 in New York

		// During quiet hours, threats are sent; the rest are held.
		e.Observe(threatEntry("", "kids", "kids-ipad", "evil.example"))
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "home", Client: "192.168.1.2"})
		e.Observe(querylog.Entry{Time: time.Now(), Profile: "home", Client: "192.168.1.3"})
		e.ListFailed("threat-intel", fmt.Errorf("HTTP 503"))
		synctest.Wait()
		if got := rec.titles(); !slices.Equal(got, []string{"Threat blocked on kids-ipad"}) {
			t.Fatalf("during quiet hours, sent %q", got)
		}

		// At 07:00, what was held is sent: one alert as itself, several
		// summarized, by kind.
		time.Sleep(9 * time.Hour) // 07:01
		synctest.Wait()
		got := rec.titles()
		slices.Sort(got)                                                                                         // two workers deliver
		want := []string{"3 new device alerts during quiet hours", "Blocklist didn't load: Threat intelligence"} // with kids-ipad's
		if !slices.Equal(got, want) {
			t.Fatalf("after quiet hours, sent %q, want %q", got, want)
		}
	})
}

func TestEngine_TenantIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, rec := startEngine(t, Options{})
		defer e.Close()
		for _, scope := range []string{"", "smiths", "joneses"} {
			addDestination(t, e, scope)
		}
		if _, err := e.SetSettings("smiths", Settings{Kinds: []Kind{KindThreat, KindListFailed}}); err == nil {
			t.Error("a tenant turned on list-failed alerts")
		}

		e.Observe(threatEntry("smiths", "smith-kids", "ipad", "smith-threat.example"))
		e.Observe(threatEntry("joneses", "jones-kids", "ipad", "jones-threat.example"))
		e.Observe(threatEntry("", "lab", "pc", "operator-threat.example"))
		e.ListFailed("scams", fmt.Errorf("HTTP 404"))
		synctest.Wait()

		got := map[string][]string{}
		for _, s := range rec.take() {
			got[s.scope] = append(got[s.scope], cmp.Or(s.alert.Details.Name, s.alert.Details.List))
			if s.alert.Scope != s.scope {
				t.Errorf("alert for %q sent to %q", s.alert.Scope, s.scope)
			}
		}
		slices.Sort(got[""])
		want := map[string][]string{
			"smiths":  {"smith-threat.example"},
			"joneses": {"jones-threat.example"},
			"":        {"operator-threat.example", "scams"},
		}
		for scope, names := range want {
			if !slices.Equal(got[scope], names) {
				t.Errorf("scope %q got %q, want %q", scope, got[scope], names)
			}
		}
	})
}

func TestEngine_NoDestinationsNoAlerts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, rec := startEngine(t, Options{})
		defer e.Close()
		e.Observe(threatEntry("", "kids", "kids-ipad", "evil.example"))
		synctest.Wait()
		if got := rec.take(); len(got) != 0 {
			t.Errorf("sent %+v with no destinations", got)
		}
		if _, err := e.Test(t.Context(), ""); err == nil {
			t.Error("tested with no destinations")
		}

		// Once there's one, every kind is on by default.
		addDestination(t, e, "")
		settings, _, _ := e.Get("")
		if !slices.Equal(settings.Kinds, Kinds) {
			t.Errorf("default kinds = %q", settings.Kinds)
		}
		if tenant, _, _ := e.Get("smiths"); slices.Contains(tenant.Kinds, KindListFailed) {
			t.Errorf("a tenant's default kinds include %s", KindListFailed)
		}
	})
}

func TestEngine_ObserveNeverBlocks(t *testing.T) {
	e, err := newEngine(Options{QueueSize: 4}) // not started: nothing reads
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10 {
			e.Observe(threatEntry("", "kids", "kids-ipad", "evil.example"))
		}
		for range 20 {
			e.ListFailed("threat-intel", fmt.Errorf("boom"))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked on a full queue")
	}
	if got := e.Dropped(); got != 6+4 {
		t.Errorf("Dropped() = %d, want 10", got)
	}
}

func TestEngine_TestAlert(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, rec := startEngine(t, Options{})
		defer e.Close()
		a := addDestination(t, e, "smiths")
		b, _, err := e.AddDestination(context.Background(), "smiths", NewDestination{Type: Webhook, URL: "https://hooks.example/doh"})
		if err != nil {
			t.Fatal(err)
		}
		// Even with every kind off, and during quiet hours, a test is sent.
		if _, err := e.SetSettings("smiths", Settings{Kinds: []Kind{}, QuietHours: &QuietHours{Start: "00:00", End: "23:59"}}); err != nil {
			t.Fatal(err)
		}
		results, err := e.Test(t.Context(), "smiths")
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != 2 || !results[0].OK || !results[1].OK || results[0].Destination != a.ID || results[1].Destination != b.ID {
			t.Errorf("results = %+v", results)
		}
		if got := rec.titles(); len(got) != 2 || got[0] != "Test alert from doh" {
			t.Errorf("sent %q", got)
		}
		_, dests, deliveries := e.Get("smiths")
		if len(deliveries) != 2 || dests[0].LastSuccess.IsZero() {
			t.Errorf("recorded %+v, destinations %+v", deliveries, dests)
		}
		if _, err := e.Test(t.Context(), "joneses"); err == nil {
			t.Error("tested another tenant's destinations")
		}
	})
}

// TestWriter_DocumentedExamples keeps the examples in
// docs/protections.md#alerts true.
func TestWriter_DocumentedExamples(t *testing.T) {
	w := writer{origin: "https://admin.dns.example.com", profileName: func(id string) string {
		return map[string]string{"kids": "Kids' tablets", "home": "Home"}[id]
	}}
	link := "https://admin.dns.example.com/#/logs?device=kids-ipad&profile=kids&q=evil-c2.example&status=blocked"

	threat := w.threat(new(threatEntry("smiths", "kids", "kids-ipad", "evil-c2.example")))
	if want := "doh blocked evil-c2.example, a known malware, phishing, or command-and-control domain (Threat intelligence list), for Kids' tablets. Nothing reached it. See it: " + link; threat.Body != want {
		t.Errorf("threat body:\n%s\nwant:\n%s", threat.Body, want)
	}
	if threat.Details.Link != link || threat.Details.Detail != "blocked by threat-intel" {
		t.Errorf("threat details = %+v", threat.Details)
	}

	w.origin = ""
	device := w.newDevice(&querylog.Entry{Profile: "home", Client: "192.168.1.50", Hostname: "living-room-tv"})
	if want := "living-room-tv started using doh, with the Home profile. Its address is 192.168.1.50."; !strings.HasPrefix(device.Body, want) || device.Title != "New device: living-room-tv" {
		t.Errorf("new device = %q: %s", device.Title, device.Body)
	}
	failing := w.failing("", time.Now(), 34, 120, "")
	if want := "In the last 5 minutes, 34 of 120 lookups (28%) failed, so some sites and apps may not load."; !strings.HasPrefix(failing.Body, want) {
		t.Errorf("failing = %s", failing.Body)
	}
	list := w.listFailed(time.Now(), "threat-intel", fmt.Errorf("HTTP 503"))
	if list.Title != "Blocklist didn't load: Threat intelligence" || !strings.HasPrefix(list.Body, "doh couldn't load the Threat intelligence list (threat-intel): HTTP 503.") {
		t.Errorf("list failed = %q: %s", list.Title, list.Body)
	}
}
