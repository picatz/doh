// Package blocklist matches domain names against filter lists, for
// blocking ads, trackers, and malware at the DNS level.
//
// It reads the formats commonly used to publish DNS blocklists, the same
// ones github.com/picatz/cube's rulegen turns into browser rules, and
// normalizes domains the same way:
//
//	||ads.example.com^       Adblock Plus: the domain and its subdomains
//	@@||cdn.example.com^     Adblock Plus exception: never block these
//	0.0.0.0 ads.example.com  hosts file: exactly this name
//	ads.example.com          domain list: exactly this name
//	*.ads.example.com        wildcard: the domain and its subdomains
//
// DNS sees only names, not URLs or the pages that load them, so Adblock
// Plus rules with paths or modifiers (other than $important) are skipped,
// as DNS blockers such as AdGuard Home do.
//
// Unlike rulegen, which turns every entry into a browser rule covering
// subdomains, hosts file and domain list entries match exactly. That's the
// convention for DNS lists, whose authors publish separate wildcard lists
// (or Adblock Plus rules) when they mean subdomains too.
package blocklist

import (
	"bufio"
	"io"
	"iter"
	"net/netip"
	"strings"
)

// Rule is a parsed blocklist rule.
type Rule struct {
	// Domain is the lower-case domain name the rule applies to, without a
	// trailing dot.
	Domain string

	// Subdomains reports whether the rule also applies to every subdomain
	// of Domain, rather than to Domain alone.
	Subdomains bool

	// Allow reports whether the rule is an exception, which prevents
	// matching names from being blocked by any other rule.
	Allow bool
}

// Rules returns the rules in r, one per line, skipping comments, blank
// lines, and rules DNS can't apply. A read error ends the sequence.
func Rules(r io.Reader) iter.Seq2[Rule, error] {
	return func(yield func(Rule, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)

		for sc.Scan() {
			for rule := range parseLine(sc.Text()) {
				if !yield(rule, nil) {
					return
				}
			}
		}

		if err := sc.Err(); err != nil {
			yield(Rule{}, err)
		}
	}
}

// parseLine returns the rules on one line: none for comments and
// unsupported rules, and possibly several for a hosts file entry.
func parseLine(line string) iter.Seq[Rule] {
	return func(yield func(Rule) bool) {
		line = strings.TrimSpace(line)

		switch {
		case line == "", line[0] == '!', line[0] == '#', line[0] == '[', isCosmetic(line):
			return
		case strings.HasPrefix(line, "@@||"):
			if domain, ok := parseABP(line[len("@@||"):]); ok {
				yield(Rule{Domain: domain, Subdomains: true, Allow: true})
			}
		case strings.HasPrefix(line, "||"):
			if domain, ok := parseABP(line[len("||"):]); ok {
				yield(Rule{Domain: domain, Subdomains: true})
			}
		default:
			// Drop trailing comments, as hosts files allow.
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}

			fields := strings.Fields(line)
			switch {
			case len(fields) == 0:
				return
			case len(fields) > 1:
				// A hosts file entry: an address, then names.
				if _, err := netip.ParseAddr(fields[0]); err != nil {
					return
				}
				for _, name := range fields[1:] {
					if domain, ok := normalize(name); ok && !isLocalName(domain) {
						if !yield(Rule{Domain: domain}) {
							return
						}
					}
				}
			case strings.HasPrefix(fields[0], "*."):
				if domain, ok := normalize(fields[0][len("*."):]); ok {
					yield(Rule{Domain: domain, Subdomains: true})
				}
			default:
				// A domain list entry. Like cube's rulegen, require a dot so
				// stray words aren't taken for names.
				if domain, ok := normalize(fields[0]); ok && strings.Contains(domain, ".") {
					yield(Rule{Domain: domain})
				}
			}
		}
	}
}

// isCosmetic reports whether line is a cosmetic or scriptlet rule, using
// the same markers as cube's rulegen. These hide page elements, and don't
// affect which names resolve.
func isCosmetic(line string) bool {
	for _, marker := range []string{"##", "#@#", "#$#", "#@#$#", "#%#", "#@%#", "#?#"} {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

// parseABP parses the part of an Adblock Plus domain rule after "||",
// such as "ads.example.com^" or "ads.example.com^$important".
//
// DNS can't evaluate modifiers about the requesting page or resource type,
// so rules with any modifier but $important are skipped, along with
// $badfilter rules that disable others.
func parseABP(rule string) (string, bool) {
	rule, options, _ := strings.Cut(rule, "$")
	for option := range strings.SplitSeq(options, ",") {
		if option = strings.TrimSpace(option); option != "" && option != "important" {
			return "", false
		}
	}

	domain, rest, _ := strings.Cut(rule, "^")
	if rest != "" && rest != "|" {
		return "", false // a path or other URL parts follow the domain
	}

	return normalize(domain)
}

// normalize lower-cases name, trims leading and trailing dots, and drops an
// explicit port, as cube's rulegen does, reporting whether the result is a
// valid domain name rather than an address or URL fragment.
func normalize(name string) (string, bool) {
	name = strings.Trim(strings.ToLower(name), ".")

	if host, port, ok := strings.Cut(name, ":"); ok && port != "" && strings.Trim(port, "0123456789") == "" {
		name = host
	}

	if name == "" || len(name) > 253 {
		return "", false
	}

	if _, err := netip.ParseAddr(name); err == nil {
		return "", false
	}

	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for _, c := range []byte(label) {
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
	}

	return name, true
}

// isLocalName reports whether name is one of the local names hosts files
// map to loopback addresses, which mustn't be blocked.
func isLocalName(name string) bool {
	switch name {
	case "localhost", "localhost.localdomain", "local", "broadcasthost",
		"ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
		"ip6-allnodes", "ip6-allrouters", "ip6-allhosts":
		return true
	}
	return false
}

// List is an immutable set of block and allow rules, safe for concurrent
// use. Build one with a [Builder].
type List struct {
	sources []string
	block   map[string]ref
	allow   map[string]ref
}

// ref records where a rule came from, and whether it covers subdomains.
type ref struct {
	source     uint16 // index into List.sources
	subdomains bool
}

// Verdict is the result of looking up a name in a [List].
type Verdict struct {
	// Blocked reports whether the name is blocked.
	Blocked bool

	// Rule is the rule that decided the verdict, if any: a block rule if
	// Blocked, or an exception that overrode one.
	Rule Rule

	// Source names the list the rule came from.
	Source string
}

// Lookup reports whether name is blocked. Exceptions take precedence over
// block rules, however specific either is.
func (l *List) Lookup(name string) Verdict {
	if l == nil {
		return Verdict{}
	}

	name = strings.ToLower(strings.TrimSuffix(name, "."))

	if rule, source, ok := l.match(l.allow, name, true); ok {
		return Verdict{Rule: rule, Source: source}
	}

	if rule, source, ok := l.match(l.block, name, false); ok {
		return Verdict{Blocked: true, Rule: rule, Source: source}
	}

	return Verdict{}
}

// match finds the most specific rule in rules that applies to name: an
// exact match, or a rule covering subdomains of one of its parents. allow
// reports whether rules are exceptions.
func (l *List) match(rules map[string]ref, name string, allow bool) (Rule, string, bool) {
	for domain := name; ; {
		if r, ok := rules[domain]; ok && (domain == name || r.subdomains) {
			return Rule{Domain: domain, Subdomains: r.subdomains, Allow: allow}, l.sources[r.source], true
		}

		_, parent, found := strings.Cut(domain, ".")
		if !found {
			return Rule{}, "", false
		}
		domain = parent
	}
}

// Len returns the number of block rules in the list.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.block)
}

// Builder accumulates rules from several sources into a [List].
// The zero value is ready to use.
type Builder struct {
	sources []string
	block   map[string]ref
	allow   map[string]ref
}

// Add adds the rules in r, attributing them to source, and returns how
// many it added.
//
// Rules are only added once r has been read without error, so a source
// that fails partway through adds nothing.
func (b *Builder) Add(source string, r io.Reader) (int, error) {
	var rules []Rule
	for rule, err := range Rules(r) {
		if err != nil {
			return 0, err
		}
		rules = append(rules, rule)
	}

	index := b.source(source)
	for _, rule := range rules {
		b.add(index, rule)
	}

	return len(rules), nil
}

// Block blocks each domain and its subdomains, attributing the rules to
// source. Invalid domains are ignored.
func (b *Builder) Block(source string, domains ...string) {
	b.addDomains(source, false, domains)
}

// Allow prevents each domain and its subdomains from being blocked,
// attributing the rules to source. Invalid domains are ignored.
func (b *Builder) Allow(source string, domains ...string) {
	b.addDomains(source, true, domains)
}

func (b *Builder) addDomains(source string, allow bool, domains []string) {
	index := b.source(source)
	for _, d := range domains {
		if domain, ok := normalize(strings.TrimPrefix(d, "*.")); ok {
			b.add(index, Rule{Domain: domain, Subdomains: true, Allow: allow})
		}
	}
}

// source returns the index for a source name, adding it if new.
func (b *Builder) source(name string) uint16 {
	for i, s := range b.sources {
		if s == name {
			return uint16(i)
		}
	}
	b.sources = append(b.sources, name)
	return uint16(len(b.sources) - 1)
}

func (b *Builder) add(source uint16, rule Rule) {
	rules := &b.block
	if rule.Allow {
		rules = &b.allow
	}
	if *rules == nil {
		*rules = make(map[string]ref)
	}

	// Keep the broader rule when a domain appears more than once.
	if existing, ok := (*rules)[rule.Domain]; ok && existing.subdomains {
		return
	}
	(*rules)[rule.Domain] = ref{source: source, subdomains: rule.Subdomains}
}

// List returns the list of rules added so far. The builder can't be used
// afterwards.
func (b *Builder) List() *List {
	l := &List{sources: b.sources, block: b.block, allow: b.allow}
	*b = Builder{}
	return l
}
