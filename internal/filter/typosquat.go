package filter

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// brand is a name typosquatting protection guards.
type brand struct {
	// name is the brand's label, as in paypal.com, without hyphens.
	name string

	// edits is the edit distance, 0 to 2, within which names match: for
	// names long enough, and unusual enough, that few legitimate domains
	// are that close. It's capped by the name's length: one edit needs
	// typoFuzzyMin letters, and two typoFuzzy2Min.
	edits int

	// domains are the registrable domains the brand uses; the first is
	// the one people know, which explanations name.
	domains []string

	// skel is name's skeleton.
	skel string
}

// maxEdits returns the edit distance within which names match b.
func (b *brand) maxEdits() int {
	switch {
	case len(b.name) < typoFuzzyMin:
		return 0
	case len(b.name) < typoFuzzy2Min:
		return min(b.edits, 1)
	}
	return min(b.edits, 2)
}

// Typosquatting thresholds.
const (
	// typoFuzzyMin is the shortest brand name matched within an edit
	// distance of one, and typoFuzzy2Min within two.
	typoFuzzyMin  = 6
	typoFuzzy2Min = 13

	// typoSkeletonMin is the shortest brand name matched by look-alike
	// characters, and typoConcatMin the shortest matched run together
	// with risk words, as in paypallogin.
	typoSkeletonMin = 4
	typoConcatMin   = 5

	// maxLabel is the longest DNS label.
	maxLabel = 63
)

// typo is the compiled brand list.
var typo = func() (t struct {
	owned     domainSet           // every brand's domains, and trustedDomains
	labels    map[string]bool     // brands' names and their domains' labels
	byName    map[string]*brand   // brands by name
	bySkel    map[string]*brand   // brands of typoSkeletonMin letters or more, by skeleton
	deletes   map[string][]*brand // one-edit brands, by skeleton with up to one letter deleted
	far       []*brand            // two-edit brands, checked one by one
	nearMax   int                 // the longest one-edit brand skeleton
	risk      map[string]bool
	riskSkels []string
	riskFirst [256][]string // riskSkels by first byte
	riskLast  [256][]string // riskSkels by last byte
}) {
	t.owned = newDomainSet(trustedDomains)
	t.labels = make(map[string]bool)
	t.byName = make(map[string]*brand)
	t.bySkel = make(map[string]*brand)
	t.risk = make(map[string]bool)
	t.deletes = make(map[string][]*brand)
	for i := range brands {
		b := &brands[i]
		var buf [maxLabel]byte
		b.skel = string(appendSkeleton(buf[:0], b.name))
		t.labels[b.name] = true
		if _, ok := t.byName[b.name]; !ok {
			t.byName[b.name] = b
		}
		if _, ok := t.bySkel[b.skel]; !ok && len(b.name) >= typoSkeletonMin {
			t.bySkel[b.skel] = b
		}
		switch b.maxEdits() {
		case 1:
			t.nearMax = max(t.nearMax, len(b.skel))
			for d := -1; d < len(b.skel); d++ {
				key := b.skel
				if d >= 0 {
					key = b.skel[:d] + b.skel[d+1:]
				}
				if !slices.Contains(t.deletes[key], b) {
					t.deletes[key] = append(t.deletes[key], b)
				}
			}
		case 2:
			t.far = append(t.far, b)
		}
		for _, d := range b.domains {
			t.owned[d] = true
			label, _, _ := strings.Cut(d, ".")
			t.labels[label] = true
		}
	}
	for _, w := range riskWords {
		t.risk[w] = true
		var buf [maxLabel]byte
		if s := string(appendSkeleton(buf[:0], w)); !slices.Contains(t.riskSkels, s) {
			t.riskSkels = append(t.riskSkels, s)
			t.riskFirst[s[0]] = append(t.riskFirst[s[0]], s)
			t.riskLast[s[len(s)-1]] = append(t.riskLast[s[len(s)-1]], s)
		}
	}
	return t
}()

// Typosquat reports whether name looks like one of the brand domains
// phishing imitates most, and why, as in "looks like paypal.com:
// paypa1.com swaps look-alike characters". It flags registrable domains
// whose label, compared with a brand's name:
//
//   - adds hyphens, as in pay-pal.com,
//   - swaps look-alike characters, as in paypa1.com, rnicrosoft.com
//     (rn for m), or vvalmart.com (vv for w),
//   - is a letter off (inserted, deleted, replaced, or two swapped), or
//     two letters off for a few long names, for brands whose names
//     aren't ordinary words, or
//   - adds risk words, as in paypal-login.com or securepaypal.com,
//
// and names that put a brand's domain inside another, as in
// paypal.com.example.net, or pair a brand with risk words in subdomains,
// as in paypal-login.example.net or paypal.verify.example.web.app.
//
// A brand's own domains, and names with a brand's exact label under any
// suffix, such as paypal.co.uk, are never flagged, so swapped TLDs aren't
// detected. Neither are names under content delivery networks and DNS
// blocklists, whose host names embed other domains by design, or
// internationalized labels, which [Homograph] checks.
func Typosquat(name string) (string, bool) {
	name = canonical(name)
	return typosquat(name, Registrable(name))
}

// typosquat is [Typosquat] for a canonical name and its registrable
// domain.
func typosquat(name, reg string) (string, bool) {
	if reg == "" {
		return "", false
	}
	if _, ok := infraDomains.match(reg); ok {
		return "", false
	}
	_, userContent := userContentDomains.match(reg)
	if !userContent {
		if _, ok := typo.owned.match(reg); ok {
			return "", false
		}
	}

	label := reg[:strings.IndexByte(reg, '.')]
	if !userContent && !typo.labels[label] {
		if b, how, ok := typoLabel(label); ok {
			return fmt.Sprintf("looks like %s: %s %s", b.domains[0], reg, how), true
		}
	}

	if sub := strings.TrimSuffix(name, reg); sub != "" {
		if b, how, ok := typoSubdomain(sub, label); ok {
			return fmt.Sprintf("looks like %s: %s %s", b.domains[0], name, how), true
		}
	}
	return "", false
}

// typoLabel reports whether label, a registrable domain's own label,
// imitates a brand, and how.
func typoLabel(label string) (*brand, string, bool) {
	if len(label) > maxLabel || strings.HasPrefix(label, "xn--") {
		return nil, "", false
	}

	var sbuf, kbuf [maxLabel]byte
	stripped := appendStripped(sbuf[:0], label)
	skel := appendSkeleton(kbuf[:0], label)

	if b, ok := typo.byName[string(stripped)]; ok {
		return b, "adds hyphens", true
	}
	if b, ok := typo.bySkel[string(skel)]; ok {
		return b, "swaps look-alike characters", true
	}

	// A letter off: two strings within one edit share a string with at
	// most one letter deleted from each, so look skel and its deletions
	// up among brands' and theirs, and confirm with the edit distance.
	if b := typoNear(skel); b != nil {
		return b, "is a letter off", true
	}
	for _, b := range typo.far {
		if d := len(skel) - len(b.skel); d > 2 || d < -2 {
			continue
		}
		switch editDistance(skel, b.skel, 2) {
		case 1:
			return b, "is a letter off", true
		case 2:
			return b, "is two letters off", true
		}
	}

	// Risk words, as separate words.
	if strings.Contains(label, "-") {
		var found *brand
		var risk string
		for tok := range strings.SplitSeq(label, "-") {
			if b := brandToken(tok); b != nil {
				found = cmpBrand(found, b)
			} else if typo.risk[tok] {
				risk = tok
			}
		}
		if found != nil && risk != "" {
			return found, fmt.Sprintf("adds %q", risk), true
		}
	}

	// Risk words run together, as in securepaypallogin: a brand's
	// skeleton between runs of risk words' skeletons.
	if b, ok := riskConcat(skel); ok {
		return b, "adds risk words", true
	}
	return nil, "", false
}

// typoNear returns a one-edit brand whose skeleton is exactly one edit
// from skel, or nil.
func typoNear(skel []byte) *brand {
	if len(skel) > typo.nearMax+1 || len(skel) > maxLabel {
		return nil
	}
	var buf [maxLabel]byte
	for d := -1; d < len(skel); d++ {
		key := skel
		if d >= 0 {
			key = append(append(buf[:0], skel[:d]...), skel[d+1:]...)
		}
		for _, b := range typo.deletes[string(key)] {
			if editDistance(skel, b.skel, 1) == 1 {
				return b
			}
		}
	}
	return nil
}

// cmpBrand returns the first of a and b in the brand list, so matches
// don't depend on the order words appear in.
func cmpBrand(a, b *brand) *brand {
	if a == nil || (b != nil && b.name < a.name) {
		return b
	}
	return a
}

// riskConcat reports whether skel is a brand's skeleton, of
// typoConcatMin letters or more, with risk words' skeletons run together
// before it, after it, or both.
func riskConcat(skel []byte) (*brand, bool) {
	n := len(skel)
	// prefix[i] is whether skel[:i] is made of risk words, and suffix[j]
	// whether skel[j:] is.
	var prefix, suffix [maxLabel + 1]bool
	prefix[0], suffix[n] = true, true
	for i := range n {
		if !prefix[i] {
			continue
		}
		for _, w := range typo.riskFirst[skel[i]] {
			if i+len(w) <= n && string(skel[i:i+len(w)]) == w {
				prefix[i+len(w)] = true
			}
		}
	}
	for j := n; j > 0; j-- {
		if !suffix[j] {
			continue
		}
		for _, w := range typo.riskLast[skel[j-1]] {
			if j-len(w) >= 0 && string(skel[j-len(w):j]) == w {
				suffix[j-len(w)] = true
			}
		}
	}
	for i := 0; i <= n; i++ {
		if !prefix[i] {
			continue
		}
		for j := n; j-i >= typoConcatMin; j-- {
			if !suffix[j] || (i == 0 && j == n) {
				continue
			}
			if b, ok := typo.bySkel[string(skel[i:j])]; ok && len(b.name) >= typoConcatMin {
				return b, true
			}
		}
	}
	return nil, false
}

// typoSubdomain reports whether sub, the labels of a name left of its
// registrable domain (with a trailing dot), imitates a brand: by
// containing a brand's domain, as in paypal.com.example.net, or a brand
// with a risk word, in sub or in label, the registrable domain's own.
func typoSubdomain(sub, label string) (*brand, string, bool) {
	sub = strings.TrimSuffix(sub, ".")

	var found *brand
	var risk string
	for rest := sub; rest != ""; {
		var l string
		l, rest, _ = strings.Cut(rest, ".")

		// The brand's domain inside another: paypal.com.example.net, or
		// paypal.com-secure.example.net.
		if b := brandToken(l); b != nil {
			next, _, _ := strings.Cut(rest, ".")
			if rest == "" {
				next = label // the registrable domain's label, as in paypal.com-secure.net
			}
			if tld, _, _ := strings.Cut(next, "-"); isTLD(tld) {
				return b, "puts " + b.name + "." + tld + " inside another domain", true
			}
		}

		for tok := range strings.SplitSeq(l, "-") {
			if b := brandToken(tok); b != nil {
				found = cmpBrand(found, b)
			} else if typo.risk[tok] {
				risk = tok
			}
		}
	}
	if found == nil {
		return nil, "", false
	}
	if risk == "" {
		for tok := range strings.SplitSeq(label, "-") {
			if typo.risk[tok] {
				risk = tok
				break
			}
		}
	}
	if risk != "" {
		return found, fmt.Sprintf("pairs %s with %q on another domain", found.name, risk), true
	}
	return nil, "", false
}

// brandToken returns the brand tok names, or for names long enough,
// looks like, or nil.
func brandToken(tok string) *brand {
	if b, ok := typo.byName[tok]; ok {
		return b
	}
	if len(tok) < typoSkeletonMin-1 || len(tok) > maxLabel {
		return nil
	}
	var buf [maxLabel]byte
	return typo.bySkel[string(appendSkeleton(buf[:0], tok))]
}

// isTLD reports whether s is a country-code top-level domain, or one of
// the original generic ones, that names a brand's domain inside another,
// as in paypal.com.example.net. Newer generic TLDs are ordinary words
// (app, cloud, news), as common in host names as they are in domains.
func isTLD(s string) bool {
	switch s {
	case "com", "net", "org", "gov", "edu", "info", "biz":
		return true
	}
	if len(s) != 2 {
		return false
	}
	ps, icann := publicsuffix.PublicSuffix(s)
	return icann && ps == s
}

// appendStripped appends s without hyphens to dst.
func appendStripped(dst []byte, s string) []byte {
	for i := range len(s) {
		if s[i] != '-' {
			dst = append(dst, s[i])
		}
	}
	return dst
}

// appendSkeleton appends the skeleton of s, a lower-case ASCII label, to
// dst: s with hyphens removed and characters that look alike in common
// fonts mapped to one, so that look-alikes share a skeleton. 0 becomes o;
// 1 and i become l; 3 becomes e; 5 becomes s; and the pairs rn, vv, and
// cl become m, w, and d.
func appendSkeleton(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		var next byte
		if i+1 < len(s) {
			next = s[i+1]
		}
		switch {
		case c == '-':
			continue
		case c == '0':
			c = 'o'
		case c == '1' || c == 'i':
			c = 'l'
		case c == '3':
			c = 'e'
		case c == '5':
			c = 's'
		case c == 'r' && next == 'n':
			c, i = 'm', i+1
		case c == 'v' && next == 'v':
			c, i = 'w', i+1
		case c == 'c' && next == 'l':
			c, i = 'd', i+1
		}
		dst = append(dst, c)
	}
	return dst
}

// editDistance returns the optimal string alignment distance between a
// and b: the fewest insertions, deletions, substitutions, and swaps of
// adjacent characters that turn one into the other (the restricted form
// of Damerau-Levenshtein distance). It returns max+1 for anything over
// max, and for strings longer than a label.
func editDistance(a []byte, b string, max int) int {
	if len(a) > maxLabel || len(b) > maxLabel {
		return max + 1
	}
	var rows [3][maxLabel + 1]uint8 // distances fit: labels are at most 63 bytes
	prev2, prev, cur := &rows[0], &rows[1], &rows[2]
	for j := 0; j <= len(b); j++ {
		prev[j] = uint8(j)
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = uint8(i)
		best := cur[0]
		for j := 1; j <= len(b); j++ {
			cost := uint8(1)
			if a[i-1] == b[j-1] {
				cost = 0
			}
			v := min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				v = min(v, prev2[j-2]+1)
			}
			cur[j] = v
			best = min(best, v)
		}
		if int(best) > max {
			return max + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return min(int(prev[len(b)]), max+1)
}
