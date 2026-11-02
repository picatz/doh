package alerts

import (
	"cmp"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/picatz/doh/internal/blocklist"
	"github.com/picatz/doh/internal/querylog"
)

// Reasons for blocking, as the query log records them. They're defined
// by internal/filter, which this package can't import, since filter
// imports internal/api, which imports this package; reasons_test.go
// checks they agree.
const (
	reasonList            = "list"
	reasonCNAME           = "cname"
	reasonHomograph       = "homograph"
	reasonTunneling       = "tunneling"
	reasonRebinding       = "rebinding"
	reasonNewlyRegistered = "newly-registered"
	reasonBypass          = "bypass"
	reasonTyposquatting   = "typosquatting"
	reasonDGA             = "dga"
	reasonSafeBrowsing    = "safe-browsing"
)

// ThreatReasons are the reasons for blocking a query, as the query log
// records them, that make it a threat, besides a list in the security
// category.
var ThreatReasons = []string{reasonHomograph, reasonTunneling, reasonRebinding, reasonNewlyRegistered, reasonBypass, reasonTyposquatting, reasonDGA, reasonSafeBrowsing}

// threatPhrases describe what each security list's names are, after
// "doh blocked NAME, ".
var threatPhrases = map[string]string{
	blocklist.ThreatIntelPreset: "a known malware, phishing, or command-and-control domain",
	"threat-intel-full":         "a known malware, phishing, or command-and-control domain",
	"scams":                     "a known scam or fake shop",
	"abused-tlds":               "in a top-level domain mostly used for spam and abuse",
	"dynamic-dns":               "a dynamic DNS name, which malware uses to move its servers around",
	"bypass-services":           "an encrypted DNS, VPN, or proxy service that routes around doh",
}

// securityList returns the preset a list name names, if it's in the
// security category.
func securityList(name string) (blocklist.Preset, bool) {
	for _, p := range blocklist.Catalog {
		if p.Name == name {
			return p, p.Category == blocklist.CategorySecurity
		}
	}
	return blocklist.Preset{}, false
}

// isThreat reports whether e is a query blocked by a security
// protection. Blocking a canary, which asks whether bypassing is allowed,
// isn't one.
func isThreat(e *querylog.Entry, canary func(string) bool) bool {
	if e.Status != querylog.StatusBlocked || e.Profile == "" {
		return false
	}
	switch e.Reason {
	case reasonList, reasonCNAME:
		_, ok := securityList(e.Source)
		return ok
	case reasonBypass:
		return canary == nil || !canary(e.Name)
	}
	return slices.Contains(ThreatReasons, e.Reason)
}

// writer writes alerts' words.
type writer struct {
	// origin is the web UI's published origin, if any, for links.
	origin string

	// profileName names a profile for people.
	profileName func(id string) string
}

// link returns a link to a view of the web UI, if it has an origin.
func (w writer) link(view string, query url.Values) string {
	if w.origin == "" {
		return ""
	}
	link := strings.TrimSuffix(w.origin, "/") + "/#/" + view
	if len(query) > 0 {
		link += "?" + query.Encode()
	}
	return link
}

// profile names e's profile.
func (w writer) profile(id string) string {
	if w.profileName != nil {
		if name := w.profileName(id); name != "" {
			return name
		}
	}
	return id
}

// deviceLabel names the device that sent e.
func deviceLabel(e *querylog.Entry) string {
	return cmp.Or(e.Device, e.Hostname, e.Client, "an unknown device")
}

// deviceQuery filters the query log to e's device.
func deviceQuery(e *querylog.Entry) url.Values {
	q := url.Values{}
	switch {
	case e.Device != "":
		q.Set("profile", e.Profile)
		q.Set("device", e.Device)
	case e.Client != "":
		q.Set("client", e.Client)
	}
	return q
}

// details returns the facts about who sent e.
func details(e *querylog.Entry) Details {
	return Details{Profile: e.Profile, Device: e.Device, Hostname: e.Hostname, Client: e.Client}
}

// threat returns the alert for a blocked threat.
func (w writer) threat(e *querylog.Entry) Alert {
	device := deviceLabel(e)
	title := "Threat blocked on " + device
	var why string
	switch e.Reason {
	case reasonList, reasonCNAME:
		p, _ := securityList(e.Source)
		if e.Reason == reasonCNAME {
			why = fmt.Sprintf("an alias of a name on the %s list", p.Title)
		} else {
			why = fmt.Sprintf("%s (%s list)", cmp.Or(threatPhrases[p.Name], "a known threat"), p.Title)
		}
	case reasonHomograph:
		why = "a look-alike of another name"
		if e.Detail != "" {
			why += " (" + e.Detail + ")"
		}
	case reasonTyposquatting:
		why = "a look-alike of a well-known brand's domain"
		if e.Detail != "" {
			why += " (" + e.Detail + ")"
		}
	case reasonDGA:
		why = "a name that looked machine-generated, as malware's are"
		if e.Detail != "" {
			why += " (" + e.Detail + ")"
		}
	case reasonSafeBrowsing:
		why = "a site Google Safe Browsing lists as dangerous"
		if e.Detail != "" {
			why += " (" + e.Detail + ")"
		}
	case reasonTunneling:
		why = "which looked like data being carried in or out over DNS"
		if e.Detail != "" {
			why += " (" + e.Detail + ")"
		}
	case reasonRebinding:
		why = "whose answer pointed into the private network, a trick called DNS rebinding"
		if e.Rule != "" {
			why += " (it answered " + e.Rule + ")"
		}
	case reasonNewlyRegistered:
		why = "a domain registered only recently, as phishing and malware domains often are"
		if e.Detail != "" {
			why += " (" + e.Detail + ")"
		}
	case reasonBypass:
		title = "Bypass blocked on " + device
		why = "a service that would route around doh's protection"
		if e.Detail != "" {
			why += " (" + e.Detail + ")"
		}
	}

	q := deviceQuery(e)
	q.Set("q", e.Name)
	q.Set("status", string(querylog.StatusBlocked))
	link := w.link("logs", q)

	var b strings.Builder
	fmt.Fprintf(&b, "doh blocked %s, %s, for %s. Nothing reached it.", e.Name, why, w.profile(e.Profile))
	if link != "" {
		b.WriteString(" See it: " + link)
	}

	d := details(e)
	d.Name, d.Reason, d.List, d.Detail, d.Link = e.Name, e.Reason, e.Source, e.Detail, link
	return Alert{Kind: KindThreat, Title: title, Body: b.String(), Time: e.Time, Details: d}
}

// newDevice returns the alert for a device not seen before.
func (w writer) newDevice(e *querylog.Entry) Alert {
	device := deviceLabel(e)
	link := w.link("logs", deviceQuery(e))

	var b strings.Builder
	fmt.Fprintf(&b, "%s started using doh, with the %s profile.", device, w.profile(e.Profile))
	if e.Client != "" && device != e.Client {
		fmt.Fprintf(&b, " Its address is %s.", e.Client)
	}
	if link != "" {
		b.WriteString(" If you don't recognize it, see what it's been looking up: " + link)
	} else {
		b.WriteString(" If you don't recognize it, check what's connected to your network.")
	}

	d := details(e)
	d.Link = link
	return Alert{Kind: KindNewDevice, Title: "New device: " + device, Body: b.String(), Time: e.Time, Details: d}
}

// failing returns the alert for failing lookups. Tenants aren't told how
// the server is run, so their alerts leave out the error.
func (w writer) failing(scope string, now time.Time, errors, queries int, lastErr string) Alert {
	q := url.Values{"status": {string(querylog.StatusError)}, "since": {now.Add(-FailingWindow).UTC().Format(time.RFC3339)}}
	link := w.link("logs", q)

	var b strings.Builder
	fmt.Fprintf(&b, "In the last %d minutes, %d of %d lookups (%d%%) failed, so some sites and apps may not load. doh answers from its cache where it can.",
		int(FailingWindow.Minutes()), errors, queries, errors*100/max(queries, 1))
	d := Details{Queries: queries, Errors: errors, Link: link}
	if scope == "" {
		if lastErr != "" {
			fmt.Fprintf(&b, " The latest error: %s.", lastErr)
			d.Error = lastErr
		}
		b.WriteString(` Check the upstreams' health with "doh status".`)
	} else {
		b.WriteString(" This is usually a problem reaching the internet; if it keeps happening, tell whoever runs your doh server.")
	}
	if link != "" {
		b.WriteString(" See them: " + link)
	}
	return Alert{Kind: KindFailing, Title: "Lookups are failing", Body: b.String(), Time: now, Details: d}
}

// listFailed returns the alert for a blocklist that didn't load.
func (w writer) listFailed(now time.Time, name string, err error) Alert {
	title := name
	for _, p := range blocklist.Catalog {
		if p.Name == name {
			title = p.Title
		}
	}
	link := w.link("overview", nil)
	var b strings.Builder
	fmt.Fprintf(&b, "doh couldn't load the %s list (%s): %v. Profiles that use it keep the rules it last loaded, if any, and doh tries again at the next refresh.", title, name, err)
	if link != "" {
		b.WriteString(" See it: " + link)
	}
	return Alert{Kind: KindListFailed, Title: "Blocklist didn't load: " + title, Body: b.String(), Time: now,
		Details: Details{List: name, Error: err.Error(), Link: link}}
}

// test returns a test alert.
func (w writer) test(now time.Time) Alert {
	body := "This is a test. If you can read it, doh's alerts reach you here."
	link := w.link("overview", nil)
	if link != "" {
		body += " " + link
	}
	return Alert{Kind: KindTest, Title: "Test alert from doh", Body: body, Time: now, Details: Details{Link: link}}
}

// burst returns the summary of alerts held back in a burst: count more of
// kind, about subject (a device, or "" for the scope), including names.
func (w writer) burst(kind Kind, subject string, count int, names []string, link string, now time.Time) Alert {
	var title, body string
	switch kind {
	case KindThreat:
		title = fmt.Sprintf("%d more threats blocked on %s in the last hour", count, subject)
		body = fmt.Sprintf("doh blocked %d more threats on %s in the last hour, including %s. Nothing reached them.", count, subject, listOf(names))
	case KindNewDevice:
		title = fmt.Sprintf("%d more new devices in the last hour", count)
		body = fmt.Sprintf("%d more devices started using doh in the last hour, including %s. If you don't recognize them, look at what they've been looking up.", count, listOf(names))
	default:
		title = fmt.Sprintf("%d more %s alerts in the last hour", count, kind.label())
		body = fmt.Sprintf("%d more %s alerts in the last hour, including %s.", count, kind.label(), listOf(names))
	}
	if link != "" {
		body += " See them: " + link
	}
	return Alert{Kind: kind, Title: title, Body: body, Time: now, Details: Details{Count: count, Names: names, Link: link}}
}

// maxHeldListed bounds the alerts a quiet hours summary lists.
const maxHeldListed = 10

// quiet returns the summary of alerts of one kind held during quiet
// hours.
func (w writer) quiet(kind Kind, held []Alert, total int, now time.Time) Alert {
	var b strings.Builder
	fmt.Fprintf(&b, "While quiet hours were on, doh held %s:", plural(total, kind.label()+" alert"))
	var names []string
	for _, a := range held[:min(len(held), maxHeldListed)] {
		fmt.Fprintf(&b, "\n- %s (%s)", a.Title, a.Time.Format("15:04 MST"))
		names = append(names, a.Title)
	}
	if more := total - min(len(held), maxHeldListed); more > 0 {
		fmt.Fprintf(&b, "\n- and %d more", more)
	}
	link := w.link("overview", nil)
	if link != "" {
		b.WriteString("\nSee them: " + link)
	}
	return Alert{Kind: kind, Title: fmt.Sprintf("%s during quiet hours", plural(total, kind.label()+" alert")), Body: b.String(), Time: now,
		Details: Details{Count: total, Names: names, Link: link}}
}

// listOf joins names as a list in a sentence: "a", "a and b", or "a, b,
// and c".
func listOf(names []string) string {
	switch len(names) {
	case 0:
		return "nothing named"
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return strings.Join(names[:len(names)-1], ", ") + ", and " + names[len(names)-1]
}

// plural counts n of unit, as "1 alert" or "2 alerts".
func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
