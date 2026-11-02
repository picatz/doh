package alerts_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/picatz/doh/internal/alerts"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/filter"
	"github.com/picatz/doh/internal/querylog"
)

// TestThreatReasons checks that the reasons alerts treats as threats are
// the filter's own, which this package can't import.
func TestThreatReasons(t *testing.T) {
	want := []string{filter.ReasonHomograph, filter.ReasonTunneling, filter.ReasonRebinding, filter.ReasonNewlyRegistered, filter.ReasonBypass,
		filter.ReasonTyposquatting, filter.ReasonDGA, filter.ReasonSafeBrowsing}
	if !slices.Equal(alerts.ThreatReasons, want) {
		t.Errorf("ThreatReasons = %q, want the filter's %q", alerts.ThreatReasons, want)
	}
}

// TestSecurityListReasons checks, through the public API, that blocks
// with the filter's list and CNAME reasons, by a security list, are
// threats, and by any other list aren't.
func TestSecurityListReasons(t *testing.T) {
	titles := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		titles <- r.Header.Get("Title") + " " + r.Header.Get("Tags")
	}))
	defer srv.Close()

	e, err := alerts.New(alerts.Options{Canary: filter.Canary})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, _, err := e.AddDestination(context.Background(), "", alerts.NewDestination{Type: alerts.Ntfy, URL: srv.URL + "/ops"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetSettings("", alerts.Settings{Kinds: []alerts.Kind{alerts.KindThreat}}); err != nil {
		t.Fatal(err)
	}

	blocked := func(device, name, reason, source string) querylog.Entry {
		return querylog.Entry{Time: time.Now(), Profile: "home", Device: device, Name: name, Rule: name, Status: querylog.StatusBlocked, Reason: reason, Source: source}
	}
	e.Observe(blocked("ads", "ads.example", filter.ReasonList, "hagezi-normal"))
	e.Observe(blocked("canary", "use-application-dns.net", filter.ReasonBypass, ""))
	e.Observe(blocked("listed", "evil.example", filter.ReasonList, blocklist.ThreatIntelPreset))
	e.Observe(blocked("aliased", "cdn.evil.example", filter.ReasonCNAME, "scams"))

	var got []string
	for range 2 {
		select {
		case title := <-titles:
			got = append(got, title)
		case <-time.After(10 * time.Second):
			t.Fatalf("got %q, want two threats", got)
		}
	}
	slices.Sort(got)
	if want := []string{"Threat blocked on aliased shield", "Threat blocked on listed shield"}; !slices.Equal(got, want) {
		t.Errorf("alerts = %q, want %q", got, want)
	}
	select {
	case extra := <-titles:
		t.Errorf("a non-threat alerted: %q", extra)
	case <-time.After(200 * time.Millisecond):
	}
}
