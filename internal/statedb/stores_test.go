package statedb

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/audit"
	"github.com/picatz/doh/internal/signin"
)

func sessionID(s string) signin.SessionID { return signin.SessionID(sha256.Sum256([]byte(s))) }

func TestSessions_RoundTripAndSurviveReopening(t *testing.T) {
	db, path := openTest(t)
	ctx := t.Context()
	now := time.Now().Truncate(time.Microsecond)
	want := signin.StoredSession{
		Session: signin.Session{Person: "p1", Name: "Kent", Role: signin.RoleAdmin, Tenant: "smiths", Method: "passkey",
			Created: now, Expires: now.Add(12 * time.Hour)},
		LastSeen: now,
	}
	s := db.Sessions()
	if err := s.Put(ctx, sessionID("a"), signin.SessionID{}, want, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.Touch(ctx, sessionID("a"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Touching never moves the clock back.
	if err := s.Touch(ctx, sessionID("a"), now); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, ok, err := db.Sessions().Get(ctx, sessionID("a"))
	if err != nil || !ok {
		t.Fatalf("after reopening: %v, %v", ok, err)
	}
	want.LastSeen = now.Add(time.Minute)
	if got.Person != want.Person || got.Name != want.Name || got.Role != want.Role || got.Tenant != want.Tenant ||
		got.Method != want.Method || got.Pending || !got.Created.Equal(want.Created) || !got.Expires.Equal(want.Expires) || !got.LastSeen.Equal(want.LastSeen) {
		t.Errorf("session = %+v, want %+v", got, want)
	}
	if _, ok, _ := db.Sessions().Get(ctx, sessionID("b")); ok {
		t.Error("found a session never stored")
	}
}

func TestSessions_ReplaceDeleteAndSweep(t *testing.T) {
	db, _ := openTest(t)
	s, ctx, now := db.Sessions(), t.Context(), time.Now()
	put := func(id, person string, pending bool, lastSeen, expires time.Time) {
		t.Helper()
		err := s.Put(ctx, sessionID(id), signin.SessionID{}, signin.StoredSession{
			Session:  signin.Session{Person: person, Name: "n", Role: signin.RoleReader, Method: "link", Pending: pending, Created: now, Expires: expires},
			LastSeen: lastSeen,
		}, 100)
		if err != nil {
			t.Fatal(err)
		}
	}
	has := func(id string) bool {
		_, ok, err := s.Get(ctx, sessionID(id))
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	put("old", "", false, now, now.Add(time.Hour))
	// A new session replaces the one its browser had: fixation can't
	// keep the old ID alive.
	if err := s.Put(ctx, sessionID("new"), sessionID("old"), signin.StoredSession{
		Session: signin.Session{Name: "n", Role: signin.RoleAdmin, Method: "link", Created: now, Expires: now.Add(time.Hour)}, LastSeen: now,
	}, 100); err != nil {
		t.Fatal(err)
	}
	if has("old") || !has("new") {
		t.Error("replacing didn't remove the old session")
	}

	put("ann1", "ann", false, now, now.Add(time.Hour))
	put("ann2", "ann", false, now, now.Add(time.Hour))
	put("bob", "bob", false, now, now.Add(time.Hour))
	if err := s.DeletePerson(ctx, "ann"); err != nil {
		t.Fatal(err)
	}
	if has("ann1") || has("ann2") || !has("bob") {
		t.Error("removing a person's sessions removed the wrong ones")
	}
	// An empty person is no one: link sessions stay.
	if err := s.DeletePerson(ctx, ""); err != nil || !has("new") {
		t.Errorf("removing no one's sessions: %v", err)
	}

	put("expired", "", false, now, now.Add(time.Minute))
	put("idle", "", false, now.Add(-3*time.Hour), now.Add(time.Hour))
	if err := s.Sweep(ctx, now.Add(2*time.Minute), 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if has("expired") || has("idle") || !has("bob") {
		t.Error("sweeping removed the wrong sessions")
	}
	if err := s.Delete(ctx, sessionID("bob")); err != nil || has("bob") {
		t.Errorf("deleting: %v", err)
	}
}

// Pending sessions, which anyone can start, only ever displace each
// other, least recently seen first.
func TestSessions_LimitEvictsLeastRecentOfTheSameKind(t *testing.T) {
	db, _ := openTest(t)
	s, ctx, now := db.Sessions(), t.Context(), time.Now()
	put := func(id string, pending bool, seen time.Duration) {
		t.Helper()
		err := s.Put(ctx, sessionID(id), signin.SessionID{}, signin.StoredSession{
			Session:  signin.Session{Name: "n", Role: signin.RoleAdmin, Method: "link", Pending: pending, Created: now, Expires: now.Add(time.Hour)},
			LastSeen: now.Add(seen),
		}, 3)
		if err != nil {
			t.Fatal(err)
		}
	}
	put("signed-in", false, 0)
	for i := range 10 {
		put("pending"+strconv.Itoa(i), true, time.Duration(i)*time.Second)
	}
	var pending, complete int
	if err := db.r.QueryRowContext(ctx, "SELECT count(*) FILTER (WHERE pending), count(*) FILTER (WHERE NOT pending) FROM sessions").Scan(&pending, &complete); err != nil {
		t.Fatal(err)
	}
	if pending != 3 || complete != 1 {
		t.Errorf("%d pending and %d complete sessions, want 3 and 1", pending, complete)
	}
	for _, id := range []string{"pending7", "pending8", "pending9", "signed-in"} {
		if _, ok, _ := s.Get(ctx, sessionID(id)); !ok {
			t.Errorf("%s was evicted", id)
		}
	}
}

func TestSetupLinks_ExpireAndAreBounded(t *testing.T) {
	db, _ := openTest(t)
	l, ctx, now := db.SetupLinks(), t.Context(), time.Now()
	key := func(i int) [32]byte { return sha256.Sum256([]byte(strconv.Itoa(i))) }
	for i := range 5 {
		if err := l.Create(ctx, key(i), SetupLink{Profile: "p" + strconv.Itoa(i), Expires: now.Add(time.Duration(10+i) * time.Minute)}, now, 3); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 5 {
		_, ok, err := l.Lookup(ctx, key(i), now)
		if err != nil {
			t.Fatal(err)
		}
		if want := i >= 2; ok != want {
			t.Errorf("link %d found %v, want %v: the soonest to expire go first", i, ok, want)
		}
	}
	if _, ok, _ := l.Lookup(ctx, key(4), now.Add(14*time.Minute)); ok {
		t.Error("an expired link was found")
	}
	if link, ok, _ := l.Lookup(ctx, key(4), now.Add(14*time.Minute-time.Nanosecond)); !ok || link.Profile != "p4" {
		t.Error("a link just before it expires wasn't found")
	}
}

// clock is an adjustable time, for replay caches.
type clock struct{ t atomic.Pointer[time.Time] }

func newClock() *clock          { c := new(clock); now := time.Now(); c.t.Store(&now); return c }
func (c *clock) Now() time.Time { return *c.t.Load() }
func (c *clock) Advance(d time.Duration) {
	next := c.Now().Add(d)
	c.t.Store(&next)
}

func TestReplayCache_AcceptsEachProofOnce(t *testing.T) {
	db, path := openTest(t)
	ctx, c := t.Context(), newClock()
	cache, err := db.ReplayCache(ctx, "api", 100, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	exp := c.Now().Add(2 * time.Minute)
	if seen, err := cache.Seen(ctx, "jti-1", exp); seen || err != nil {
		t.Fatalf("first use: seen %v, %v", seen, err)
	}
	if seen, err := cache.Seen(ctx, "jti-1", exp); !seen || err != nil {
		t.Fatalf("replay: seen %v, %v; want refused", seen, err)
	}

	// Another cache's proofs are its own.
	other, _ := db.ReplayCache(ctx, "exchange", 100, c.Now)
	if seen, _ := other.Seen(ctx, "jti-1", exp); seen {
		t.Error("caches share proofs")
	}

	// A replay after a restart is refused too.
	db.Close()
	db, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cache, _ = db.ReplayCache(ctx, "api", 100, c.Now)
	if seen, err := cache.Seen(ctx, "jti-1", exp); !seen || err != nil {
		t.Errorf("replay after reopening: seen %v, %v; want refused", seen, err)
	}

	// Once it can't be fresh, it's forgotten.
	c.Advance(2 * time.Minute)
	if seen, err := cache.Seen(ctx, "jti-1", c.Now().Add(2*time.Minute)); seen || err != nil {
		t.Errorf("after expiring: seen %v, %v", seen, err)
	}
}

// A full cache refuses new proofs rather than forget one that could be
// replayed, until some expire.
func TestReplayCache_RefusesWhenFull(t *testing.T) {
	db, path := openTest(t)
	ctx, c := t.Context(), newClock()
	cache, _ := db.ReplayCache(ctx, "api", 3, c.Now)
	for i := range 3 {
		if seen, err := cache.Seen(ctx, "jti-"+strconv.Itoa(i), c.Now().Add(time.Duration(i+1)*time.Minute)); seen || err != nil {
			t.Fatalf("proof %d: %v, %v", i, seen, err)
		}
	}
	if _, err := cache.Seen(ctx, "jti-new", c.Now().Add(time.Minute)); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("a proof beyond the bound: %v, want ErrReplayCacheFull", err)
	}
	if seen, err := cache.Seen(ctx, "jti-0", c.Now().Add(time.Minute)); seen || !errors.Is(err, ErrReplayCacheFull) {
		t.Errorf("a replay into a full cache: seen %v, %v; want refused", seen, err)
	}

	// The bound survives a restart.
	db.Close()
	db, _ = Open(ctx, path)
	defer db.Close()
	cache, _ = db.ReplayCache(ctx, "api", 3, c.Now)
	if _, err := cache.Seen(ctx, "jti-new", c.Now().Add(time.Minute)); !errors.Is(err, ErrReplayCacheFull) {
		t.Errorf("after reopening, a proof beyond the bound: %v", err)
	}

	// Once the first expires, there's room for one.
	c.Advance(time.Minute)
	if seen, err := cache.Seen(ctx, "jti-new", c.Now().Add(time.Minute)); seen || err != nil {
		t.Errorf("after one expired: %v, %v", seen, err)
	}
	if _, err := cache.Seen(ctx, "jti-newer", c.Now().Add(time.Minute)); !errors.Is(err, ErrReplayCacheFull) {
		t.Errorf("full again: %v", err)
	}
	// Replays of the unexpired are still refused.
	if seen, err := cache.Seen(ctx, "jti-2", c.Now().Add(time.Minute)); !seen && err == nil {
		t.Error("a replay was accepted")
	}

	// A sweep makes room too, and the cache knows it.
	c.Advance(5 * time.Minute)
	if err := db.Sweep(ctx, c.Now(), SweepOptions{}); err != nil {
		t.Fatal(err)
	}
	if cache.count != 0 {
		t.Errorf("after a sweep, the cache counts %d", cache.count)
	}
}

func TestReplayCache_ConcurrentReplaysOneWins(t *testing.T) {
	db, _ := openTest(t)
	ctx := t.Context()
	cache, _ := db.ReplayCache(ctx, "api", 1000, nil)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if seen, err := cache.Seen(ctx, "same", time.Now().Add(time.Minute)); err == nil && !seen {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if n := accepted.Load(); n != 1 {
		t.Errorf("a proof was accepted %d times", n)
	}
}

func TestAlertMemory(t *testing.T) {
	db, path := openTest(t)
	m, ctx, now := db.AlertMemory(), t.Context(), time.Now()

	isNew, since, err := m.SeeDevice(ctx, "smiths", "client:192.168.1.5", now)
	if err != nil || !isNew || !since.Equal(now) {
		t.Fatalf("first device: new %v, since %v, %v", isNew, since, err)
	}
	isNew, since, _ = m.SeeDevice(ctx, "smiths", "client:192.168.1.5", now.Add(time.Hour))
	if isNew || !since.Equal(now) {
		t.Errorf("seen again: new %v, since %v", isNew, since)
	}
	// Each scope has its own devices.
	if isNew, _, _ := m.SeeDevice(ctx, "", "client:192.168.1.5", now); !isNew {
		t.Error("the operator shares a tenant's devices")
	}

	if ok, err := m.Claim(ctx, "smiths", "threat", "k", now, time.Hour); !ok || err != nil {
		t.Fatalf("claim: %v, %v", ok, err)
	}
	if ok, _ := m.Claim(ctx, "smiths", "threat", "k", now.Add(59*time.Minute), time.Hour); ok {
		t.Error("claimed again within the window")
	}
	if ok, _ := m.Claim(ctx, "", "threat", "k", now, time.Hour); !ok {
		t.Error("another scope's claim blocked this one")
	}

	// It all survives reopening.
	db.Close()
	db, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m = db.AlertMemory()
	if isNew, _, _ := m.SeeDevice(ctx, "smiths", "client:192.168.1.5", now); isNew {
		t.Error("a device was forgotten on reopening")
	}
	if ok, _ := m.Claim(ctx, "smiths", "threat", "k", now.Add(time.Minute), time.Hour); ok {
		t.Error("an alert was forgotten on reopening")
	}
	if ok, _ := m.Claim(ctx, "smiths", "threat", "k", now.Add(time.Hour), time.Hour); !ok {
		t.Error("an alert's window didn't end")
	}

	// Forgetting a scope forgets its devices, by foreign key, and its
	// alerts, and nothing of anyone else's.
	if err := m.Forget(ctx, "smiths"); err != nil {
		t.Fatal(err)
	}
	if isNew, _, _ := m.SeeDevice(ctx, "smiths", "client:192.168.1.5", now); !isNew {
		t.Error("a forgotten scope's device is known")
	}
	if isNew, _, _ := m.SeeDevice(ctx, "", "client:192.168.1.5", now); isNew {
		t.Error("forgetting a tenant forgot the operator's device")
	}
}

func TestAlertMemory_BoundsDevicesAndImports(t *testing.T) {
	db, _ := openTest(t)
	m, ctx, start := db.AlertMemory(), t.Context(), time.Now()
	seen := make(map[string]time.Time)
	for i := range alerts.MaxSeenDevices + 5 {
		seen["client:"+strconv.Itoa(i)] = start.Add(time.Duration(i) * time.Second)
	}
	importer := m.(alerts.DeviceImporter)
	if err := importer.ImportDevices(ctx, "", start.Add(-24*time.Hour), seen); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.r.QueryRowContext(ctx, "SELECT count(*) FROM alert_devices").Scan(&n); err != nil || n != alerts.MaxSeenDevices {
		t.Errorf("%d devices after importing, want %d", n, alerts.MaxSeenDevices)
	}
	// The least recently seen were the ones left out.
	if isNew, since, _ := m.SeeDevice(ctx, "", "client:"+strconv.Itoa(alerts.MaxSeenDevices+4), start); isNew || !since.Equal(start.Add(-24*time.Hour)) {
		t.Errorf("most recent device: new %v, since %v", isNew, since)
	}
	if isNew, _, _ := m.SeeDevice(ctx, "", "client:0", start.Add(time.Hour)); !isNew {
		t.Error("the least recently seen device was kept")
	}
	// Seeing one more forgets the least recently seen, keeping the bound.
	if err := db.r.QueryRowContext(ctx, "SELECT count(*) FROM alert_devices").Scan(&n); err != nil || n != alerts.MaxSeenDevices {
		t.Errorf("%d devices, want %d", n, alerts.MaxSeenDevices)
	}
	if _, _, err := m.SeeDevice(ctx, "", strings.Repeat("x", maxDeviceName+1), start); err == nil {
		t.Error("an over-long device name was kept")
	}
}

func TestAudit_ListsNewestFirstByPage(t *testing.T) {
	db, path := openTest(t)
	store, ctx := db.Audit(), t.Context()
	start := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	for i := range 25 {
		if err := store.Record(ctx, audit.Event{
			Time: start.Add(time.Duration(i) * time.Minute), Action: "profile.updated",
			Actor: audit.Actor{Kind: audit.ActorPerson, ID: "p1", Name: "Kent"}, Target: audit.Target{Type: "profile", ID: "kids"},
			Details: map[string]string{"n": strconv.Itoa(i)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	db, _ = Open(ctx, path)
	defer db.Close()
	store = db.Audit()

	var got []string
	f := audit.Filter{AllTenants: true, Limit: 10}
	for pages := 0; ; pages++ {
		page, err := store.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Events {
			got = append(got, e.Details["n"])
		}
		if page.NextPageToken == "" {
			if pages != 2 {
				t.Errorf("%d pages, want 3", pages+1)
			}
			break
		}
		f.PageToken = page.NextPageToken
	}
	if len(got) != 25 || got[0] != "24" || got[24] != "0" {
		t.Errorf("events = %v, want 24 down to 0", got)
	}

	page, _ := store.List(ctx, audit.Filter{AllTenants: true, Before: start.Add(3 * time.Minute)})
	if len(page.Events) != 3 || page.Events[0].Details["n"] != "2" {
		t.Errorf("before 09:03: %+v", page.Events)
	}
	e := page.Events[0]
	if e.Actor.Name != "Kent" || e.Actor.Kind != audit.ActorPerson || e.Target.ID != "kids" || !e.Time.Equal(start.Add(2*time.Minute)) || e.ID == "" {
		t.Errorf("event = %+v", e)
	}
}

// Tenants see only their own events, whatever they ask for, and a forged
// page token can't widen that.
func TestAudit_TenantScoping(t *testing.T) {
	db, _ := openTest(t)
	store, ctx, now := db.Audit(), t.Context(), time.Now()
	for _, tenant := range []string{"", "smiths", "joneses", "smiths"} {
		if err := store.Record(ctx, audit.Event{Time: now, Tenant: tenant, Action: "profile.updated", Actor: audit.Actor{Kind: audit.ActorToken}}); err != nil {
			t.Fatal(err)
		}
	}
	tenants := func(f audit.Filter) []string {
		t.Helper()
		page, err := store.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range page.Events {
			out = append(out, e.Tenant)
		}
		return out
	}
	if got := tenants(audit.Filter{Tenant: "smiths"}); len(got) != 2 || got[0] != "smiths" || got[1] != "smiths" {
		t.Errorf("smiths see %q", got)
	}
	if got := tenants(audit.Filter{Tenant: ""}); len(got) != 1 || got[0] != "" {
		t.Errorf("the operator's own: %q", got)
	}
	if got := tenants(audit.Filter{AllTenants: true}); len(got) != 4 {
		t.Errorf("all: %q", got)
	}
	forged := audit.EncodePageToken(1 << 40)
	if got := tenants(audit.Filter{Tenant: "smiths", PageToken: forged}); len(got) != 2 || got[0] != "smiths" {
		t.Errorf("with a forged token, smiths see %q", got)
	}
	if _, err := store.List(ctx, audit.Filter{Tenant: "smiths", PageToken: "not-a-token"}); !errors.Is(err, audit.ErrInvalidFilter) {
		t.Errorf("an invalid token: %v", err)
	}
}

func TestAudit_FiltersAndRetention(t *testing.T) {
	db, _ := openTest(t)
	store, ctx, now := db.Audit(), t.Context(), time.Now()
	for _, e := range []audit.Event{
		{Time: now.Add(-400 * 24 * time.Hour), Action: "profile.updated", Actor: audit.Actor{Kind: audit.ActorPerson, ID: "p1", Name: "Kent"}},
		{Time: now, Action: "service_account.key.revoked", Actor: audit.Actor{Kind: audit.ActorPerson, ID: "p1", Name: "Kent"}},
		{Time: now, Action: "serviceXaccount.created", Actor: audit.Actor{Kind: audit.ActorToken, ID: "admin", Name: "admin token"}},
		{Time: now, Action: "profile", Actor: audit.Actor{Kind: audit.ActorToken, ID: "admin", Name: "admin token"}},
		{Time: now, Action: "profiles.x", Actor: audit.Actor{Kind: audit.ActorToken, ID: "admin", Name: "admin token"}},
	} {
		if err := store.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	actions := func(f audit.Filter) []string {
		t.Helper()
		f.AllTenants = true
		page, err := store.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range page.Events {
			out = append(out, e.Action)
		}
		return out
	}
	if got := actions(audit.Filter{Action: "service_account"}); len(got) != 1 || got[0] != "service_account.key.revoked" {
		t.Errorf("service_account: %q (an underscore isn't a wildcard)", got)
	}
	if got := actions(audit.Filter{Action: "profile"}); len(got) != 2 {
		t.Errorf("profile: %q, want profile and profile.updated, not profiles.x", got)
	}
	if got := actions(audit.Filter{Actor: "Kent"}); len(got) != 2 {
		t.Errorf("by name: %q", got)
	}
	if got := actions(audit.Filter{Actor: "admin"}); len(got) != 3 {
		t.Errorf("by ID: %q", got)
	}
	if err := db.Sweep(ctx, now, SweepOptions{AuditRetention: 365 * 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	if got := actions(audit.Filter{Action: "profile.updated"}); len(got) != 0 {
		t.Errorf("past retention: %q", got)
	}
}

func TestAudit_NormalizesWhatItRecords(t *testing.T) {
	db, _ := openTest(t)
	store, ctx := db.Audit(), t.Context()
	details := map[string]string{}
	for i := range audit.MaxDetails + 10 {
		details[strconv.Itoa(1000+i)] = strings.Repeat("é", audit.MaxValueLength)
	}
	if err := store.Record(ctx, audit.Event{Time: time.Now(), Action: strings.Repeat("a", 1000), Summary: "bad \xff utf-8", Details: details}); err != nil {
		t.Fatal(err)
	}
	page, _ := store.List(ctx, audit.Filter{AllTenants: true})
	e := page.Events[0]
	if len(e.Details) != audit.MaxDetails || len(e.Action) > audit.MaxFieldLength || !strings.HasSuffix(e.Action, "…") {
		t.Errorf("%d details, action of %d bytes", len(e.Details), len(e.Action))
	}
	for k, v := range e.Details {
		if len(v) > audit.MaxValueLength || !strings.HasSuffix(v, "…") {
			t.Errorf("detail %s: %d bytes", k, len(v))
		}
	}
	if e.Summary != "bad � utf-8" {
		t.Errorf("summary = %q", e.Summary)
	}
}

// _ checks that the stores satisfy the interfaces they're for.
var (
	_ signin.Sessions       = sessions{}
	_ alerts.Memory         = alertMemory{}
	_ alerts.DeviceImporter = alertMemory{}
	_ audit.Store           = auditStore{}
)
