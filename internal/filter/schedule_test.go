package filter

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
)

// at returns a clock stopped at the given time in New York.
func at(t *testing.T, value string) func() time.Time {
	t.Helper()
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	when, err := time.ParseInLocation("Mon 2006-01-02 15:04", value, ny)
	if err != nil {
		t.Fatal(err)
	}
	return func() time.Time { return when.UTC() } // the server's clock may be in any zone
}

func kidsProfile() policy.Profile {
	return policy.Profile{
		ID:       "kids",
		TimeZone: "America/New_York",
		Services: []string{"tiktok"},
		Allow:    []string{"always.example"},
		Schedules: []policy.Schedule{
			{Name: "Bedtime", Days: []string{"sun", "mon", "tue", "wed", "thu"}, Start: "21:00", End: "07:00", BlockAll: true, Allow: []string{"school.example"}},
			{Name: "Homework", Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "15:00", End: "18:00", Services: []string{"youtube", "roblox"}, Deny: []string{"games.example"}},
		},
	}
}

func TestSchedules(t *testing.T) {
	for _, tt := range []struct {
		when, name string
		reason     string // "" when allowed
	}{
		// TikTok is always blocked.
		{"Sat 2026-11-07 12:00", "www.tiktok.com", ReasonService},
		{"Sat 2026-11-07 12:00", "v16.tiktokcdn.com", ReasonService},

		// Homework, weekdays 15:00 to 18:00.
		{"Mon 2026-11-02 15:00", "www.youtube.com", ReasonSchedule},
		{"Mon 2026-11-02 17:59", "www.roblox.com", ReasonSchedule},
		{"Mon 2026-11-02 16:00", "play.games.example", ReasonSchedule},
		{"Mon 2026-11-02 18:00", "www.youtube.com", ""}, // ends at 18:00
		{"Mon 2026-11-02 14:59", "www.youtube.com", ""},
		{"Sat 2026-11-07 16:00", "www.youtube.com", ""}, // not on weekends
		{"Mon 2026-11-02 16:00", "example.com", ""},     // only what it lists

		// Bedtime, 21:00 to 07:00 on school nights, blocks everything...
		{"Mon 2026-11-02 21:00", "example.com", ReasonSchedule},
		{"Tue 2026-11-03 06:59", "example.com", ReasonSchedule}, // Monday's bedtime, past midnight
		{"Tue 2026-11-03 07:00", "example.com", ""},
		{"Sun 2026-11-08 22:00", "example.com", ReasonSchedule}, // Sunday night is a school night
		{"Fri 2026-11-06 22:00", "example.com", ""},             // Friday isn't
		{"Sat 2026-11-07 03:00", "example.com", ""},             // nor is Friday's night into Saturday
		{"Fri 2026-11-06 03:00", "example.com", ReasonSchedule}, // Thursday's is
		// ...except its allowed sites, the profile's, and local names.
		{"Mon 2026-11-02 23:00", "www.school.example", ""},
		{"Mon 2026-11-02 23:00", "always.example", ReasonAllow},
		{"Mon 2026-11-02 23:00", "printer.lan", ""},
		{"Mon 2026-11-02 23:00", "router", ""},
	} {
		t.Run(tt.when+" "+tt.name, func(t *testing.T) {
			e := engine(t, Options{Now: at(t, tt.when)}, kidsProfile())
			var trace Trace
			d := e.Profile("kids").Check(t.Context(), Query{Name: tt.name, Type: dns.TypeA}, &trace)

			switch {
			case tt.reason == "" && d.Action != api.ActionAllow:
				t.Errorf("Check = %+v, want allowed; trace %+v", d.Decision, trace.Checks)
			case tt.reason == ReasonAllow && d.Reason != ReasonAllow:
				t.Errorf("Check = %+v, want explicitly allowed", d.Decision)
			case tt.reason != "" && tt.reason != ReasonAllow && (d.Action != api.ActionBlock || d.Reason != tt.reason):
				t.Errorf("Check = %+v, want blocked by %s; trace %+v", d.Decision, tt.reason, trace.Checks)
			}
		})
	}
}

func TestSchedules_TellPeopleWhy(t *testing.T) {
	e := engine(t, Options{Now: at(t, "Mon 2026-11-02 16:30")}, kidsProfile())
	d := e.Profile("kids").Check(t.Context(), Query{Name: "www.youtube.com", Type: dns.TypeA}, nil)
	if d.Detail != "Homework: YouTube is blocked until 18:00" || d.Source != "Homework" {
		t.Errorf("decision = %+v", d.Decision)
	}

	d = e.Profile("kids").Check(t.Context(), Query{Name: "www.tiktok.com", Type: dns.TypeA}, nil)
	if d.Detail != "TikTok is blocked" || d.Source != "tiktok" {
		t.Errorf("service decision = %+v", d.Decision)
	}

	resp := e.Profile("kids").Block(new(dns.Msg).SetQuestion("www.youtube.com.", dns.TypeA).SetEdns0(1232, false),
		e.Profile("kids").Check(t.Context(), Query{Name: "www.youtube.com", Type: dns.TypeA}, nil))
	if got := ede(resp); got == nil || got.ExtraText != "blocked: schedule" {
		t.Errorf("EDE = %v", got)
	}
}

func TestSchedules_CNAMEsCantSlipThrough(t *testing.T) {
	e := engine(t, Options{Now: at(t, "Mon 2026-11-02 16:30")}, kidsProfile())
	pr := e.Profile("kids")

	answer := func(name, target string) *dns.Msg {
		m := new(dns.Msg).SetQuestion(name, dns.TypeA)
		rr, _ := dns.NewRR(name + " 60 IN CNAME " + target)
		m.Answer = append(m.Answer, rr)
		return m
	}
	for _, tt := range []struct{ name, target string }{
		{"video.cdn.example.", "rr1---sn-abc.googlevideo.com."}, // YouTube, during homework
		{"clips.example.", "v19.tiktokcdn-us.com."},             // TikTok, always
	} {
		if d := pr.CheckResponse(Query{Name: tt.name, Type: dns.TypeA}, answer(tt.name, tt.target), nil); d.Reason != ReasonCNAME {
			t.Errorf("CNAME to %s: %+v, want blocked", tt.target, d.Decision)
		}
	}
}

func TestSchedules_TimeZones(t *testing.T) {
	// 02:00 UTC on a Tuesday is still Monday 21:00 in New York.
	utc := func() time.Time { return time.Date(2026, 11, 3, 2, 0, 0, 0, time.UTC) }
	e := engine(t, Options{Now: utc}, kidsProfile())
	if d := e.Profile("kids").Check(t.Context(), Query{Name: "example.com", Type: dns.TypeA}, nil); d.Reason != ReasonSchedule {
		t.Errorf("bedtime in the profile's time zone: %+v", d.Decision)
	}

	// The same instant is mid-morning Tuesday in Tokyo: no bedtime.
	tokyo := kidsProfile()
	tokyo.TimeZone = "Asia/Tokyo"
	e = engine(t, Options{Now: utc}, tokyo)
	if d := e.Profile("kids").Check(t.Context(), Query{Name: "example.com", Type: dns.TypeA}, nil); d.Action != api.ActionAllow {
		t.Errorf("Tokyo morning: %+v", d.Decision)
	}
}

func TestSchedules_Lists(t *testing.T) {
	reg, list := lists(t, "||social.example^\n")
	p := policy.Profile{ID: "kids", Schedules: []policy.Schedule{{Name: "Focus", Start: "00:00", End: "23:59", Lists: []string{list}}}}
	e := engine(t, Options{Lists: reg, Now: func() time.Time { return time.Date(2026, 11, 2, 12, 0, 0, 0, time.Local) }}, p)

	if got := len(e.Sources()); got != 1 {
		t.Errorf("Sources() = %d, want the schedule's list loaded", got)
	}
	if d := e.Profile("kids").Check(t.Context(), Query{Name: "www.social.example", Type: dns.TypeA}, nil); d.Reason != ReasonSchedule {
		t.Errorf("scheduled list: %+v", d.Decision)
	}
}

func TestSchedules_AllDay(t *testing.T) {
	p := policy.Profile{ID: "kids", TimeZone: "America/New_York", Schedules: []policy.Schedule{
		{Name: "Weekend off", Days: []string{"sat", "sun"}, Start: "00:00", End: "00:00", Services: []string{"youtube"}},
	}}
	for when, blocked := range map[string]bool{
		"Sat 2026-11-07 00:00": true,
		"Sun 2026-11-08 23:59": true,
		"Mon 2026-11-09 00:00": false,
		"Fri 2026-11-06 23:59": false,
	} {
		e := engine(t, Options{Now: at(t, when)}, p)
		d := e.Profile("kids").Check(t.Context(), Query{Name: "www.youtube.com", Type: dns.TypeA}, nil)
		if (d.Action == api.ActionBlock) != blocked {
			t.Errorf("%s: %+v, want blocked %v", when, d.Decision, blocked)
		}
		if blocked && d.Detail != "Weekend off: YouTube is blocked today" {
			t.Errorf("%s: detail %q", when, d.Detail)
		}
	}
}
