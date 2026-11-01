package filter

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/policy"
	"github.com/picatz/doh/internal/services"
)

// serviceSet matches names against services' domains.
type serviceSet struct {
	domains domainSet
	owner   map[string]services.Service // by domain
}

// newServiceSet returns the domains of the services with ids.
func newServiceSet(ids []string) serviceSet {
	s := serviceSet{domains: domainSet{}, owner: map[string]services.Service{}}
	for _, id := range ids {
		svc, ok := services.Lookup(id)
		if !ok {
			continue
		}
		for _, d := range svc.Domains {
			s.domains[d] = true
			s.owner[d] = svc
		}
	}
	return s
}

// match returns the service name belongs to, and the domain that matched.
func (s serviceSet) match(name string) (services.Service, string, bool) {
	d, ok := s.domains.match(name)
	if !ok {
		return services.Service{}, "", false
	}
	return s.owner[d], d, true
}

// schedule is a compiled [policy.Schedule].
type schedule struct {
	name       string
	days       [7]bool // by time.Weekday
	start, end int     // minutes since midnight
	end24      string  // End, for messages

	blockAll bool
	allow    domainSet
	deny     domainSet
	services serviceSet
	lists    []blocklist.Source
}

// compileSchedule compiles sc, which must be valid.
func compileSchedule(sc policy.Schedule) (schedule, error) {
	start, err := policy.ParseClock(sc.Start)
	if err != nil {
		return schedule{}, err
	}
	end, err := policy.ParseClock(sc.End)
	if err != nil {
		return schedule{}, err
	}

	c := schedule{
		name:     strings.TrimSpace(sc.Name),
		start:    start,
		end:      end,
		end24:    sc.End,
		blockAll: sc.BlockAll,
		allow:    newDomainSet(sc.Allow),
		deny:     newDomainSet(sc.Deny),
		services: newServiceSet(sc.Services),
	}
	for i, d := range policy.Weekdays {
		c.days[i] = len(sc.Days) == 0 || slices.Contains(sc.Days, d)
	}
	for _, l := range sc.Lists {
		src, err := blocklist.ParseSource(l)
		if err != nil {
			return schedule{}, err
		}
		c.lists = append(c.lists, src)
	}
	return c, nil
}

// active reports whether the schedule's period includes now, in the
// profile's time zone. A period that ends before it starts runs past
// midnight, so it belongs to the day it started on: a Friday 21:00 to
// 07:00 bedtime is active early on Saturday morning. One that ends when it
// starts lasts all day.
func (s schedule) active(now time.Time) bool {
	minute := now.Hour()*60 + now.Minute()
	today := now.Weekday()
	yesterday := (today + 6) % 7

	switch {
	case s.start == s.end: // all day
		return s.days[today]
	case s.start < s.end:
		return s.days[today] && s.start <= minute && minute < s.end
	}
	return (s.days[today] && minute >= s.start) || (s.days[yesterday] && minute < s.end)
}

// now returns the current time in the profile's time zone.
func (p *Profile) now() time.Time {
	return p.engine.now().In(p.location)
}

// activeSchedules returns the profile's schedules in effect now.
func (p *Profile) activeSchedules() []*schedule {
	if len(p.schedules) == 0 {
		return nil
	}
	now := p.now()
	var active []*schedule
	for i := range p.schedules {
		if p.schedules[i].active(now) {
			active = append(active, &p.schedules[i])
		}
	}
	return active
}

// serviceBlock checks the profile's blocked services.
func (p *Profile) serviceBlock(name string, t *Trace) (Decision, bool) {
	if len(p.services.domains) == 0 {
		t.Add(ReasonService, api.CheckSkip, "no services blocked")
		return Decision{}, false
	}
	if svc, d, ok := p.services.match(name); ok {
		t.Add(ReasonService, api.CheckMatch, "%s is blocked", svc.Name)
		return block(ReasonService, d, svc.ID, svc.Name+" is blocked"), true
	}
	t.Add(ReasonService, api.CheckPass, "not a blocked service")
	return Decision{}, false
}

// scheduleBlock checks the profile's schedules in effect now.
func (p *Profile) scheduleBlock(name string, t *Trace) (Decision, bool) {
	active := p.activeSchedules()
	if len(active) == 0 {
		if len(p.schedules) == 0 {
			t.Add(ReasonSchedule, api.CheckSkip, "no schedules")
		} else {
			t.Add(ReasonSchedule, api.CheckPass, "no schedule in effect at %s", p.now().Format("Mon 15:04"))
		}
		return Decision{}, false
	}

	for _, sc := range active {
		until := " until " + sc.end24
		if sc.start == sc.end {
			until = " today"
		}
		if svc, d, ok := sc.services.match(name); ok {
			t.Add(ReasonSchedule, api.CheckMatch, "%s: %s is blocked%s", sc.name, svc.Name, until)
			return block(ReasonSchedule, d, sc.name, fmt.Sprintf("%s: %s is blocked%s", sc.name, svc.Name, until)), true
		}
		if d, ok := sc.deny.match(name); ok {
			t.Add(ReasonSchedule, api.CheckMatch, "%s: %s is blocked%s", sc.name, d, until)
			return block(ReasonSchedule, d, sc.name, fmt.Sprintf("%s: %s is blocked%s", sc.name, d, until)), true
		}
		if v, ok := p.listsBlock(sc.lists, name); ok {
			t.Add(ReasonSchedule, api.CheckMatch, "%s: blocked by %s%s", sc.name, v.Source, until)
			return block(ReasonSchedule, v.Rule.Domain, sc.name, fmt.Sprintf("%s: blocked by %s%s", sc.name, v.Source, until)), true
		}
		if sc.blockAll {
			if _, ok := sc.allow.match(name); ok {
				continue
			}
			if p.engine.isLocal(name) {
				continue // the router, the printer, and other local names keep working
			}
			t.Add(ReasonSchedule, api.CheckMatch, "%s: everything is blocked%s", sc.name, until)
			return block(ReasonSchedule, name, sc.name, fmt.Sprintf("%s: everything is blocked%s", sc.name, until)), true
		}
	}

	names := make([]string, len(active))
	for i, sc := range active {
		names[i] = sc.name
	}
	t.Add(ReasonSchedule, api.CheckPass, "%s in effect, but doesn't block this", strings.Join(names, ", "))
	return Decision{}, false
}

// listsBlock returns the rule of lists that blocks name, unless one of
// them has an exception for it.
func (p *Profile) listsBlock(sources []blocklist.Source, name string) (blocklist.Verdict, bool) {
	var lists []*blocklist.List
	for _, src := range sources {
		if l := p.engine.opts.Lists.List(src); l != nil {
			lists = append(lists, l)
		}
	}
	for _, l := range lists {
		if _, ok := l.Exception(name); ok {
			return blocklist.Verdict{}, false
		}
	}
	for _, l := range lists {
		if v, ok := l.Block(name); ok {
			return v, true
		}
	}
	return blocklist.Verdict{}, false
}

// targetBlock checks a CNAME target against the profile's services and the
// schedules in effect, so an app can't slip through behind an alias.
func (p *Profile) targetBlock(target string) (Decision, bool) {
	if svc, d, ok := p.services.match(target); ok {
		return block(ReasonCNAME, d, svc.ID, "CNAME to "+target+", "+svc.Name+" is blocked"), true
	}
	for _, sc := range p.activeSchedules() {
		if svc, d, ok := sc.services.match(target); ok {
			return block(ReasonCNAME, d, sc.name, "CNAME to "+target+", "+sc.name+": "+svc.Name+" is blocked"), true
		}
		if d, ok := sc.deny.match(target); ok {
			return block(ReasonCNAME, d, sc.name, "CNAME to "+target+", blocked by "+sc.name), true
		}
	}
	return Decision{}, false
}
