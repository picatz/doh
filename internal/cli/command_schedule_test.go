package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/services"
	"github.com/spf13/cobra"
)

func TestParseDays(t *testing.T) {
	for in, want := range map[string][]string{
		"":                  nil,
		"every day":         nil,
		"every-day":         nil,
		"weekdays":          {"mon", "tue", "wed", "thu", "fri"},
		"Weekends":          {"sun", "sat"},
		"school-nights":     {"sun", "mon", "tue", "wed", "thu"},
		"school nights":     {"sun", "mon", "tue", "wed", "thu"},
		"mon-fri":           {"mon", "tue", "wed", "thu", "fri"},
		"fri-mon":           {"sun", "mon", "fri", "sat"},
		"monday, Wednesday": {"mon", "wed"},
		"sat,sun,sat":       {"sun", "sat"},
		"weekdays,weekends": nil, // all seven is every day
		"tues":              {"tue"},
	} {
		got, err := parseDays(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseDays(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"funday", "mo", "mon-", "mon-xyz", "monx", ",", "mondays"} {
		if days, err := parseDays(in); err == nil {
			t.Errorf("parseDays(%q) = %q, want an error", in, days)
		}
	}
}

func TestFormatDays(t *testing.T) {
	for want, days := range map[string][]string{
		"Every day":     nil,
		"Mon–Fri":       {"mon", "tue", "wed", "thu", "fri"},
		"Sun–Thu":       {"sun", "mon", "tue", "wed", "thu"},
		"Sat, Sun":      {"sat", "sun"},
		"Fri–Mon":       {"fri", "sat", "sun", "mon"},
		"Mon, Wed":      {"mon", "wed"},
		"Tue":           {"tue"},
		"Mon–Wed, Fri":  {"mon", "tue", "wed", "fri"},
		"Mon, Tue, Thu": {"mon", "tue", "thu"},
		"Sat–Mon":       {"sun", "mon", "sat"},
	} {
		if got := formatDays(days); got != want {
			t.Errorf("formatDays(%q) = %q, want %q", days, got, want)
		}
	}
	all := policy.Weekdays[:]
	if got := formatDays(all); got != "Every day" {
		t.Errorf("formatDays(all) = %q", got)
	}
}

func TestScheduleActive(t *testing.T) {
	// 2026-11-02 is a Monday.
	at := func(day int, hhmm string) time.Time {
		h, m := 0, 0
		fmt.Sscanf(hhmm, "%d:%d", &h, &m)
		return time.Date(2026, 11, 1+day, h, m, 0, 0, time.UTC)
	}
	homework := policy.Schedule{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "15:00", End: "18:00"}
	bedtime := policy.Schedule{Days: []string{"sun", "mon", "tue", "wed", "thu"}, Start: "21:00", End: "07:00"}
	daily := policy.Schedule{Start: "12:00", End: "13:00"}
	weekend := policy.Schedule{Days: []string{"sat", "sun"}, Start: "00:00", End: "00:00"}

	for _, tt := range []struct {
		name string
		sc   policy.Schedule
		now  time.Time
		want bool
	}{
		{"homework Monday afternoon", homework, at(1, "16:30"), true},
		{"homework starts on the minute", homework, at(1, "15:00"), true},
		{"homework ends on the minute", homework, at(1, "18:00"), false},
		{"homework Saturday", homework, at(6, "16:00"), false},
		{"bedtime Sunday night", bedtime, at(0, "22:00"), true},
		{"bedtime into Monday morning", bedtime, at(1, "06:59"), true},
		{"bedtime ends Monday 07:00", bedtime, at(1, "07:00"), false},
		{"bedtime Friday night", bedtime, at(5, "22:00"), false},
		{"bedtime Friday morning, from Thursday", bedtime, at(5, "06:00"), true},
		{"bedtime Sunday morning, from Saturday", bedtime, at(0, "06:00"), false},
		{"daily at noon", daily, at(3, "12:30"), true},
		{"weekend all day, Saturday night", weekend, at(6, "23:59"), true},
		{"weekend all day, Sunday dawn", weekend, at(0, "00:00"), true},
		{"weekend all day, Monday", weekend, at(1, "00:00"), false},
		{"bad clock", policy.Schedule{Start: "25:00", End: "07:00"}, at(1, "06:00"), false},
	} {
		if got := scheduleActive(tt.sc, tt.now); got != tt.want {
			t.Errorf("%s: scheduleActive = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDescribeBlocks(t *testing.T) {
	for want, sc := range map[string]policy.Schedule{
		"everything":                             {BlockAll: true},
		"everything but school.example":          {BlockAll: true, Allow: []string{"school.example"}},
		"YouTube, Roblox, social, games.example": {Services: []string{"youtube", "roblox"}, Lists: []string{"social"}, Deny: []string{"games.example"}},
		"someday-app":                            {Services: []string{"someday-app"}},
	} {
		if got := describeBlocks(sc); got != want {
			t.Errorf("describeBlocks(%+v) = %q, want %q", sc, got, want)
		}
	}
}

func TestCheckSchedule(t *testing.T) {
	ok := policy.Schedule{Name: "Homework", Start: "15:00", End: "18:00", Services: []string{"youtube"}}
	if err := checkSchedule(ok); err != nil {
		t.Fatalf("checkSchedule(valid) = %v", err)
	}
	allDay := ok
	allDay.Start, allDay.End = "00:00", "00:00"
	if err := checkSchedule(allDay); err != nil {
		t.Errorf("checkSchedule(all day) = %v", err)
	}
	for want, change := range map[string]func(*policy.Schedule){
		"--name":                    func(s *policy.Schedule) { s.Name = " " },
		"--start":                   func(s *policy.Schedule) { s.Start = "3pm" },
		"--end":                     func(s *policy.Schedule) { s.End = "24:00" },
		"say what to block":         func(s *policy.Schedule) { s.Services = nil },
		"only applies with":         func(s *policy.Schedule) { s.Allow = []string{"school.example"} },
		`unknown service "myspace"`: func(s *policy.Schedule) { s.Services = []string{"myspace"} },
	} {
		sc := ok
		change(&sc)
		if err := checkSchedule(sc); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("checkSchedule with %s: %v", want, err)
		}
	}
}

// profileServer is an admin API holding one profile, with entity tags,
// conditional merge patches, and optionally a change by someone else
// before the first patch.
type profileServer struct {
	mu        sync.Mutex
	profile   policy.Profile
	version   int
	interfere func(*policy.Profile) // run once, before the next patch
	patches   []string
	ifMatches []string
}

func (s *profileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer t0ken" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(api.Error{Error: "invalid token"})
		return
	}
	if r.URL.Path != "/api/v1/profiles/"+s.profile.ID {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(api.Error{Error: "no such profile"})
		return
	}
	etag := fmt.Sprintf(`"v%d"`, s.version)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("ETag", etag)
		json.NewEncoder(w).Encode(s.profile)
	case http.MethodPatch:
		body, _ := io.ReadAll(r.Body)
		s.patches = append(s.patches, string(body))
		s.ifMatches = append(s.ifMatches, r.Header.Get("If-Match"))
		if s.interfere != nil {
			interfere := s.interfere
			s.interfere = nil
			interfere(&s.profile)
			s.version++
			etag = fmt.Sprintf(`"v%d"`, s.version)
		}
		if r.Header.Get("If-Match") != etag {
			w.WriteHeader(http.StatusPreconditionFailed)
			json.NewEncoder(w).Encode(api.Error{Error: "the policy changed; reload and try again"})
			return
		}
		var patch struct {
			Schedules *[]policy.Schedule `json:"schedules"`
		}
		if err := json.Unmarshal(body, &patch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.profile.Schedules = nil
		if patch.Schedules != nil {
			s.profile.Schedules = *patch.Schedules
		}
		s.version++
		w.Header().Set("ETag", fmt.Sprintf(`"v%d"`, s.version))
		json.NewEncoder(w).Encode(s.profile)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// runSchedule runs "doh schedule args..." against s.
func runSchedule(t *testing.T, s *profileServer, args ...string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	root := &cobra.Command{Use: "doh", SilenceErrors: true}
	root.AddCommand(newScheduleCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs(append(append([]string{"schedule"}, args...), "--addr", srv.URL, "--token", "t0ken"))
	err := root.Execute()
	return out.String(), err
}

func TestScheduleAddListRemove(t *testing.T) {
	s := &profileServer{profile: policy.Profile{ID: "kids", TimeZone: "UTC"}}

	out, err := runSchedule(t, s, "list", "kids")
	if err != nil || !strings.Contains(out, "no schedules") || !strings.Contains(out, "doh schedule add kids") {
		t.Fatalf("empty list = %q, %v", out, err)
	}

	out, err = runSchedule(t, s, "add", "kids", "--name", "Bedtime", "--days", "school-nights", "--start", "21:00", "--end", "07:00", "--block-all", "--allow", "school.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`Added "Bedtime"`, "Sun–Thu 21:00–07:00", "everything but school.example", "past midnight"} {
		if !strings.Contains(out, want) {
			t.Errorf("add output %q lacks %q", out, want)
		}
	}
	if s.ifMatches[0] != `"v0"` {
		t.Errorf("If-Match = %q, want the read version", s.ifMatches[0])
	}

	if _, err := runSchedule(t, s, "add", "kids", "--name", "Homework", "--days", "mon-fri", "--start", "15:00", "--end", "18:00", "--service", "youtube"); err != nil {
		t.Fatal(err)
	}
	want := []policy.Schedule{
		{Name: "Bedtime", Days: []string{"sun", "mon", "tue", "wed", "thu"}, Start: "21:00", End: "07:00", BlockAll: true, Allow: []string{"school.example"}},
		{Name: "Homework", Days: []string{"mon", "tue", "wed", "thu", "fri"}, Start: "15:00", End: "18:00", Services: []string{"youtube"}},
	}
	if !reflect.DeepEqual(s.profile.Schedules, want) {
		t.Fatalf("schedules = %+v, want %+v", s.profile.Schedules, want)
	}

	out, err = runSchedule(t, s, "list", "kids")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"NAME", "Bedtime", "Sun–Thu", "Homework", "Mon–Fri", "15:00–18:00", "YouTube"} {
		if !strings.Contains(out, w) {
			t.Errorf("list output %q lacks %q", out, w)
		}
	}
	if strings.Contains(out, "?") {
		t.Errorf("list with a time zone shows unknown states: %q", out)
	}

	out, err = runSchedule(t, s, "list", "kids", "--json")
	var listed []policy.Schedule
	if err != nil || json.Unmarshal([]byte(out), &listed) != nil || len(listed) != 2 {
		t.Errorf("list --json = %q, %v", out, err)
	}

	// Duplicate names are refused before anything is written.
	before := len(s.patches)
	if _, err := runSchedule(t, s, "add", "kids", "--name", "bedtime", "--start", "20:00", "--end", "06:00", "--block-all"); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Errorf("duplicate add: %v", err)
	}
	if len(s.patches) != before {
		t.Error("a duplicate add patched the profile")
	}

	if _, err := runSchedule(t, s, "remove", "kids", "nope"); err == nil || !strings.Contains(err.Error(), "Bedtime, Homework") {
		t.Errorf("removing an unknown schedule: %v", err)
	}
	if _, err := runSchedule(t, s, "remove", "kids", "HOMEWORK"); err != nil {
		t.Fatal(err)
	}
	if _, err := runSchedule(t, s, "remove", "kids", "Bedtime"); err != nil {
		t.Fatal(err)
	}
	if s.profile.Schedules != nil {
		t.Errorf("schedules after removing all = %+v", s.profile.Schedules)
	}
	if last := s.patches[len(s.patches)-1]; !strings.Contains(last, `"schedules":null`) {
		t.Errorf("removing the last schedule sent %s, want a null to delete the field", last)
	}
}

func TestScheduleAdd_RetriesOnceWhenThePolicyChanged(t *testing.T) {
	s := &profileServer{
		profile: policy.Profile{ID: "kids"},
		interfere: func(p *policy.Profile) {
			p.Schedules = []policy.Schedule{{Name: "Dinner", Start: "18:00", End: "19:00", BlockAll: true}}
		},
	}
	if _, err := runSchedule(t, s, "add", "kids", "--name", "Bedtime", "--start", "21:00", "--end", "07:00", "--block-all"); err != nil {
		t.Fatal(err)
	}
	if len(s.patches) != 2 || s.ifMatches[1] != `"v1"` {
		t.Fatalf("patches = %q with If-Match %q, want a retry against the new version", s.patches, s.ifMatches)
	}
	if names := []string{s.profile.Schedules[0].Name, s.profile.Schedules[1].Name}; !reflect.DeepEqual(names, []string{"Dinner", "Bedtime"}) {
		t.Errorf("schedules = %q, want the other change kept", names)
	}
}

func TestScheduleAdd_GivesUpAfterOneRetry(t *testing.T) {
	s := &profileServer{profile: policy.Profile{ID: "kids"}}
	// Every patch races another change.
	var bump func(*policy.Profile)
	bump = func(*policy.Profile) { s.interfere = bump }
	s.interfere = bump

	_, err := runSchedule(t, s, "add", "kids", "--name", "Bedtime", "--start", "21:00", "--end", "07:00", "--block-all")
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("err = %v, want the precondition failure", err)
	}
	if len(s.patches) != 2 {
		t.Errorf("%d patches, want 2", len(s.patches))
	}
}

func TestScheduleAdd_ValidatesLocally(t *testing.T) {
	s := &profileServer{profile: policy.Profile{ID: "kids"}}
	for want, args := range map[string][]string{
		"unknown day":       {"--name", "X", "--days", "funday", "--start", "21:00", "--end", "07:00", "--block-all"},
		"--start":           {"--name", "X", "--start", "9pm", "--end", "07:00", "--block-all"},
		"say what to block": {"--name", "X", "--start", "21:00", "--end", "07:00"},
		"unknown service":   {"--name", "X", "--start", "21:00", "--end", "07:00", "--service", "myspace"},
		"only applies":      {"--name", "X", "--start", "21:00", "--end", "07:00", "--deny", "a.example", "--allow", "b.example"},
	} {
		_, err := runSchedule(t, s, append([]string{"add", "kids"}, args...)...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("add %q: %v, want %q", args, err, want)
		}
	}
	if len(s.patches) != 0 {
		t.Errorf("invalid schedules were sent: %q", s.patches)
	}
}

func TestScheduleList_WithoutTimeZone(t *testing.T) {
	s := &profileServer{profile: policy.Profile{ID: "kids", Schedules: []policy.Schedule{{Name: "Bedtime", Start: "21:00", End: "07:00", BlockAll: true}}}}
	out, err := runSchedule(t, s, "list", "kids")
	if err != nil || !strings.Contains(out, "?") || !strings.Contains(out, "time_zone=") {
		t.Errorf("list = %q, %v; want an unknown state and a time zone hint", out, err)
	}
}

func TestServicesCommand(t *testing.T) {
	exec := func(args ...string) (string, error) {
		root := &cobra.Command{Use: "doh", SilenceErrors: true}
		root.AddCommand(newServicesCommand())
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(append([]string{"services"}, args...))
		err := root.Execute()
		return out.String(), err
	}
	run := func(args ...string) string {
		out, err := exec(args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	out := run()
	for _, want := range []string{"ID", "CATEGORY", "tiktok", "TikTok", "social", "roblox", "gaming"} {
		if !strings.Contains(out, want) {
			t.Errorf("services output lacks %q:\n%s", want, out)
		}
	}
	var listed []services.Service
	if err := json.Unmarshal([]byte(run("--json")), &listed); err != nil || len(listed) != len(services.Catalog) {
		t.Errorf("services --json: %d services, %v", len(listed), err)
	}

	// A search matches IDs, names, and categories, case-insensitively.
	if out := run("CHAT"); !strings.Contains(out, "chatgpt") || !strings.Contains(out, "wechat") || strings.Contains(out, "tiktok") {
		t.Errorf("services CHAT:\n%s", out)
	}
	if err := json.Unmarshal([]byte(run("--category", "dating", "--json")), &listed); err != nil || len(listed) == 0 {
		t.Fatalf("services --category dating: %v", err)
	}
	for _, s := range listed {
		if s.Category != "dating" {
			t.Errorf("services --category dating listed %s (%s)", s.ID, s.Category)
		}
	}
	if out := run("nothing-like-this", "--json"); strings.TrimSpace(out) != "[]" {
		t.Errorf("services --json with no matches = %q, want []", out)
	}

	for args, want := range map[string]string{
		"nothing-like-this": "no services match",
		"--category=nope":   `unknown --category "nope"`,
	} {
		out, err := exec(args)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("services %s: %v, want %q", args, err, want)
		}
		if strings.Contains(out, "Usage:") {
			t.Errorf("services %s printed usage for a failed search:\n%s", args, out)
		}
	}
}

func TestPrintProfile_ServicesAndSchedules(t *testing.T) {
	var out bytes.Buffer
	p := &policy.Profile{
		ID:       "kids",
		Services: []string{"tiktok", "roblox"},
		TimeZone: "America/New_York",
		Schedules: []policy.Schedule{
			{Name: "Bedtime", Days: []string{"sun", "mon", "tue", "wed", "thu"}, Start: "21:00", End: "07:00", BlockAll: true, Allow: []string{"school.example"}},
		},
	}
	if err := printProfile(&out, p); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TikTok, Roblox", "America/New_York", "Bedtime", "Sun–Thu 21:00–07:00  everything but school.example"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("printProfile lacks %q:\n%s", want, out.String())
		}
	}
}

func TestProfileSet_ServicesIsAList(t *testing.T) {
	patch, err := mergePatch([]string{"services=tiktok"}, profileListKeys)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := json.Marshal(patch); string(got) != `{"services":["tiktok"]}` {
		t.Errorf("patch = %s", got)
	}
}
