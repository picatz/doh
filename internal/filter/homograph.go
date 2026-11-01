package filter

import (
	"slices"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Homograph reports whether name is an internationalized domain name that
// could pass for a different name, and why. It flags labels that:
//
//   - aren't valid Punycode ([RFC 3492]),
//   - contain invisible formatting characters, such as zero-width joiners,
//   - mix scripts beyond the combinations [UTS #39, Section 5.2] allows at
//     its "Highly Restrictive" level, which permits a single script, or
//     Latin with Han and Japanese kana, with Han and Bopomofo, or with Han
//     and Hangul, as in "аpple" with a Cyrillic а,
//   - spell a name entirely in Cyrillic or Greek letters that look Latin,
//     as in "аре" (a whole-script confusable, [UTS #39, Section 4]),
//     unless the TLD is one where those scripts are expected, or
//   - use Latin letters that are rarely legitimate and look like common
//     ones, such as "ɡ" (U+0261) for "g".
//
// Plain ASCII names are never flagged.
//
// [RFC 3492]: https://www.rfc-editor.org/rfc/rfc3492.html
// [UTS #39, Section 5.2]: https://www.unicode.org/reports/tr39/#Restriction_Level_Detection
// [UTS #39, Section 4]: https://www.unicode.org/reports/tr39/#Confusable_Detection
func Homograph(name string) (string, bool) {
	name = canonical(name)
	if !strings.Contains(name, "xn--") {
		return "", false
	}

	labels := strings.Split(name, ".")
	tld := labels[len(labels)-1]
	nativeTLD := nativeScriptTLD(tld)

	for _, label := range labels {
		if !strings.HasPrefix(label, "xn--") {
			continue
		}

		decoded, err := idna.Punycode.ToUnicode(label)
		if err != nil || decoded == label {
			return "invalid punycode label " + label, true
		}

		scripts := make(map[string]bool)
		allConfusable := true
		for _, r := range decoded {
			if unicode.Is(unicode.Cf, r) {
				return "invisible character in " + decoded, true
			}
			if deceptiveLatin[r] && tld != "tr" && tld != "az" {
				return "deceptive letter " + string(r) + " in " + decoded, true
			}

			script := scriptOf(r)
			if script == "" {
				continue // Common or Inherited, such as digits and hyphens
			}
			scripts[script] = true
			if !latinLookalikes[r] {
				allConfusable = false
			}
		}

		// Labels must also be valid IDNA2008 labels, which registries
		// enforce, so anything else wasn't registered for people to read.
		if _, err := idna.Lookup.ToUnicode(label); err != nil {
			return "invalid internationalized label " + label, true
		}

		if !allowedScripts(scripts) {
			return "mixed scripts (" + strings.Join(sortedKeys(scripts), ", ") + ") in " + decoded, true
		}

		if len(scripts) == 1 && allConfusable && !nativeTLD {
			for script := range scripts {
				if script == "Cyrillic" || script == "Greek" {
					return "all-" + script + " look-alike of a Latin name: " + decoded, true
				}
			}
		}
	}

	return "", false
}

// allowedScripts reports whether a label's scripts are one of the
// combinations allowed at UTS #39's Highly Restrictive level.
func allowedScripts(scripts map[string]bool) bool {
	if len(scripts) <= 1 {
		return true
	}
	for _, allowed := range [][]string{
		{"Latin", "Han", "Hiragana", "Katakana"},
		{"Latin", "Han", "Bopomofo"},
		{"Latin", "Han", "Hangul"},
	} {
		subset := true
		for s := range scripts {
			if !slices.Contains(allowed, s) {
				subset = false
				break
			}
		}
		if subset {
			return true
		}
	}
	return false
}

// scriptTables are Unicode's scripts, without Common and Inherited, which
// are shared by every script.
var scriptTables = func() []struct {
	name  string
	table *unicode.RangeTable
} {
	var tables []struct {
		name  string
		table *unicode.RangeTable
	}
	// The scripts phishing uses go first, so they're found quickly.
	common := []string{"Latin", "Cyrillic", "Greek", "Han", "Hiragana", "Katakana", "Hangul", "Arabic", "Hebrew"}
	for _, name := range common {
		tables = append(tables, struct {
			name  string
			table *unicode.RangeTable
		}{name, unicode.Scripts[name]})
	}
	for _, name := range sortedKeys(unicode.Scripts) {
		if name != "Common" && name != "Inherited" && !slices.Contains(common, name) {
			tables = append(tables, struct {
				name  string
				table *unicode.RangeTable
			}{name, unicode.Scripts[name]})
		}
	}
	return tables
}()

// scriptOf returns the name of r's script, or "" if it's Common or
// Inherited.
func scriptOf(r rune) string {
	if unicode.In(r, unicode.Common, unicode.Inherited) {
		return ""
	}
	for _, s := range scriptTables {
		if unicode.Is(s.table, r) {
			return s.name
		}
	}
	return ""
}

// latinLookalikes are lower-case Cyrillic and Greek letters that render
// like Latin letters in common fonts, as browsers' IDN display policies
// treat them.
var latinLookalikes = map[rune]bool{
	// Cyrillic
	'а': true, 'с': true, 'ԁ': true, 'е': true, 'һ': true, 'і': true, 'ј': true,
	'ӏ': true, 'о': true, 'р': true, 'ԛ': true, 'ѕ': true, 'ԝ': true, 'х': true,
	'у': true, 'ү': true, 'ъ': true, 'ь': true, 'ҽ': true, 'п': true, 'г': true,
	'ѵ': true, 'ѡ': true,
	// Greek
	'α': true, 'β': true, 'ε': true, 'ι': true, 'κ': true, 'ν': true, 'ο': true,
	'ρ': true, 'τ': true, 'υ': true, 'χ': true, 'ω': true,
}

// deceptiveLatin are Latin letters that look like ASCII letters and have
// little legitimate use in domain names. Dotless ı is allowed under
// Turkish and Azerbaijani TLDs, where it's an ordinary letter.
var deceptiveLatin = map[rune]bool{
	'ɑ': true, // U+0251 Latin alpha, for a
	'ɡ': true, // U+0261 script g, for g
	'ɩ': true, // U+0269 Latin iota, for i
	'ɪ': true, // U+026A small capital I, for i
	'ʏ': true, // U+028F small capital Y, for y
	'ı': true, // U+0131 dotless i, for i
	'ꞁ': true, // U+A781 turned l, for l
}

// nativeScriptTLD reports whether names under tld are expected to use
// Cyrillic or Greek, so all-Cyrillic or all-Greek names there are normal:
// internationalized TLDs, and country codes whose languages use them.
func nativeScriptTLD(tld string) bool {
	if strings.HasPrefix(tld, "xn--") {
		return true
	}
	switch tld {
	case "ru", "su", "ua", "by", "kz", "kg", "tj", "bg", "rs", "me", "mk", "mn", "ba", "md", "uz", "gr", "cy":
		return true
	}
	return false
}

// sortedKeys returns m's keys, sorted.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
