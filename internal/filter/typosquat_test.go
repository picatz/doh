package filter

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestTyposquat(t *testing.T) {
	for name, want := range map[string]string{
		// Hyphens, look-alike characters, and typos.
		"pay-pal.com":           "looks like paypal.com: pay-pal.com adds hyphens",
		"paypa1.com":            "looks like paypal.com: paypa1.com swaps look-alike characters",
		"paypai.net":            "looks like paypal.com: paypai.net swaps look-alike characters",
		"rnicrosoft.com":        "looks like microsoft.com: rnicrosoft.com swaps look-alike characters",
		"vvalmart.com":          "looks like walmart.com: vvalmart.com swaps look-alike characters",
		"g00gle.com":            "looks like google.com: g00gle.com swaps look-alike characters",
		"app1e.com":             "looks like apple.com: app1e.com swaps look-alike characters",
		"llnkedin.com":          "looks like linkedin.com: llnkedin.com swaps look-alike characters",
		"paypall.com.br":        "looks like paypal.com: paypall.com.br is a letter off",
		"paypla.com":            "looks like paypal.com: paypla.com is a letter off",
		"amazom.co.uk":          "looks like amazon.com: amazom.co.uk is a letter off",
		"micosoft.com":          "looks like microsoft.com: micosoft.com is a letter off",
		"faceboook.com":         "looks like facebook.com: faceboook.com is a letter off",
		"bankofamerca.com":      "looks like bankofamerica.com: bankofamerca.com is a letter off",
		"wellsfarrgo.com":       "looks like wellsfargo.com: wellsfarrgo.com is a letter off",
		"welsfarg0.com":         "looks like wellsfargo.com: welsfarg0.com is a letter off",
		"bnakofamerca.com":      "looks like bankofamerica.com: bnakofamerca.com is two letters off",
		"www.coinbsae.com":      "looks like coinbase.com: coinbsae.com is a letter off",
		"americanexpres.online": "looks like americanexpress.com: americanexpres.online is a letter off",

		// Risk words.
		"paypal-login.com":           `looks like paypal.com: paypal-login.com adds "login"`,
		"secure-paypal.net":          `looks like paypal.com: secure-paypal.net adds "secure"`,
		"paypa1-verify.com":          `looks like paypal.com: paypa1-verify.com adds "verify"`,
		"apple-id.com":               `looks like apple.com: apple-id.com adds "id"`,
		"dhl-tracking.info":          `looks like dhl.com: dhl-tracking.info adds "tracking"`,
		"paypalsecure.com":           "looks like paypal.com: paypalsecure.com adds risk words",
		"securepaypallogin.com":      "looks like paypal.com: securepaypallogin.com adds risk words",
		"appleidverify.com":          "looks like apple.com: appleidverify.com adds risk words",
		"netflixaccountupdate.co.uk": "looks like netflix.com: netflixaccountupdate.co.uk adds risk words",

		// Brands inside other domains, and with risk words in subdomains.
		"paypal.com.example.net":             "looks like paypal.com: paypal.com.example.net puts paypal.com inside another domain",
		"www.paypal.com-secure.net":          "looks like paypal.com: www.paypal.com-secure.net puts paypal.com inside another domain",
		"paypal.co.uk.example.org":           "looks like paypal.com: paypal.co.uk.example.org puts paypal.co inside another domain",
		"login.microsoft.com.evil.net":       "looks like microsoft.com: login.microsoft.com.evil.net puts microsoft.com inside another domain",
		"paypal-login.web.app":               `looks like paypal.com: paypal-login.web.app pairs paypal with "login" on another domain`,
		"paypal.verify.example.com":          `looks like paypal.com: paypal.verify.example.com pairs paypal with "verify" on another domain`,
		"customer.paypal.restored.cemaco.vn": `looks like paypal.com: customer.paypal.restored.cemaco.vn pairs paypal with "restored" on another domain`,
		"amazon.example-account.com":         `looks like amazon.com: amazon.example-account.com pairs amazon with "account" on another domain`,
		"micr0soft-login.github.io":          `looks like microsoft.com: micr0soft-login.github.io pairs microsoft with "login" on another domain`,
		"PayPal-Login.COM.":                  `looks like paypal.com: paypal-login.com adds "login"`,
	} {
		got, ok := Typosquat(name)
		if !ok || got != want {
			t.Errorf("Typosquat(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
}

func TestTyposquat_Legitimate(t *testing.T) {
	for _, name := range []string{
		// Brands and their own domains, and look-alikes they own.
		"paypal.com", "www.paypal.com", "paypalobjects.com", "t.paypal.com", "paypal.me", "paypal-community.com",
		"google.com", "accounts.google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "gmail.com",
		"login.microsoftonline.com", "outlook.office365.com", "microsoft.com", "live.com", "account.live.com",
		"appleid.apple.com", "icloud.com", "apple.com", "amazon.com", "amazonaws.com", "media-amazon.com",
		"wellsfargo.com", "connect.secure.wellsfargo.com", "secure.chase.com", "login.yahoo.com", "github.com",
		"login.salesforce.com", "accounts.binance.com", "verify.coinbase.com",

		// A brand's exact label under any suffix: swapped TLDs aren't
		// detected.
		"paypal.co.uk", "amazon.co.jp", "google.com.br", "apple.com.cn", "login.paypal.de",

		// Ordinary words a letter from a short or common-word brand.
		"apply.com", "ample.com", "chose.com", "vista.com", "eba.com", "upss.com", "dhs.gov", "irs.gov",
		"target.com", "square.com", "discover.com", "visa.com", "steam.com",

		// Words containing brands, without risk words.
		"applebees.com", "pineapple.com", "snapple.com", "amazonia.org", "googleblog.com", "chasenet.org",
		"booking-holdings.com", "ups-store.com", "paypal-business-community.com",

		// Long legitimate labels.
		"thisisaverylonglegitimatedomainnamethatgoesonandon.com", "internationalbusinessmachines.com",
		"llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",

		// Content delivery networks, blocklists, and other infrastructure.
		"www.paypal.com.edgekey.net", "www.apple.com.edgekey.net", "www.microsoft.com-c-3.edgekey.net",
		"e6858.dscx.akamaiedge.net", "www.amazon.com.cdn.cloudflare.net", "paypal.com.dbl.spamhaus.org",
		"paypal.com.multi.uribl.com", "d3ag4hukkh62yn.cloudfront.net", "paypal.map.fastly.net",

		// Brands' tenants on other companies' services.
		"paypal.okta.com", "paypal.zoom.us", "paypal.service-now.com", "apple.box.com", "paypal.zendesk.com",
		"paypal.my.salesforce.com", "paypal-my.sharepoint.com", "paypal.sharepoint.com", "netflix.github.io",
		"google.github.io", "amazon.jobs",

		// Brands in subdomains with words that aren't risk words, and
		// other TLDs that are words.
		"apple.news.example.com", "google.cloud.example.com", "amazon.app.example.net",

		// Internationalized names, which homograph protection checks.
		"xn--pypal-4ve.com", "xn--80ak6aa92e.com", "xn--mnchen-3ya.de",

		// Local and odd names.
		"localhost", "printer.lan", "paypal", "com", "", ".", "a..b", "x" + strings.Repeat("y", 80) + ".com",
	} {
		if why, ok := Typosquat(name); ok {
			t.Errorf("Typosquat(%q) = %q; want it allowed", name, why)
		}
	}
}

// TestTyposquat_PopularDomains checks that no popular domain is flagged.
// Set DOH_TRANCO to a Tranco list (rank,domain lines) to check more and
// report how many are flagged.
func TestTyposquat_PopularDomains(t *testing.T) {
	// Popular, but look-alikes whose owners aren't known: they stay
	// flagged rather than be trusted unverified.
	unknown := map[string]bool{"oneidrive.org": true, "googll.store": true}

	for _, name := range topDomains(t) {
		if why, ok := Typosquat(name); ok != unknown[name] {
			t.Errorf("Typosquat(%q) = %q, %v", name, why, ok)
		}
	}

	if path := os.Getenv("DOH_TRANCO"); path != "" {
		names := tranco(t, path)
		flagged := 0
		for _, name := range names {
			if why, ok := Typosquat(name); ok {
				flagged++
				t.Logf("flagged: %s", why)
			}
		}
		t.Logf("flagged %d of %d domains (%.4f%%)", flagged, len(names), 100*float64(flagged)/float64(len(names)))
	}
}

// topDomains returns testdata/top-domains.txt.
func topDomains(tb testing.TB) []string {
	tb.Helper()
	f, err := os.Open("testdata/top-domains.txt")
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()

	var names []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if line := strings.TrimSpace(s.Text()); line != "" && !strings.HasPrefix(line, "#") {
			names = append(names, line)
		}
	}
	if err := s.Err(); err != nil {
		tb.Fatal(err)
	}
	return names
}

// tranco reads a Tranco list's rank,domain lines.
func tranco(tb testing.TB, path string) []string {
	tb.Helper()
	f, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()

	var names []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		_, name, _ := strings.Cut(s.Text(), ",")
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func TestEditDistance(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		max  int
		want int
	}{
		{"paypal", "paypal", 2, 0},
		{"paypla", "paypal", 2, 1}, // a swap counts once
		{"paypl", "paypal", 2, 1},
		{"paypall", "paypal", 2, 1},
		{"paypbl", "paypal", 2, 1},
		{"pyapla", "paypal", 2, 2},
		{"abcdef", "paypal", 2, 3},
		{"", "abc", 5, 3},
		{"abc", "", 5, 3},
		{"ca", "abc", 5, 3}, // OSA, not unrestricted Damerau-Levenshtein, which gives 2
	} {
		if got := editDistance([]byte(tt.a), tt.b, tt.max); got != tt.want {
			t.Errorf("editDistance(%q, %q, %d) = %d, want %d", tt.a, tt.b, tt.max, got, tt.want)
		}
	}
	if got := editDistance([]byte(strings.Repeat("a", 64)), "a", 1); got != 2 {
		t.Errorf("editDistance of an over-long label = %d, want max+1", got)
	}
}

func TestSkeleton(t *testing.T) {
	for in, want := range map[string]string{
		"paypal": "paypal", "paypa1": "paypal", "pay-pal": "paypal", "rnicrosoft": "mlcrosoft",
		"vvalmart": "walmart", "clropbox": "dropbox", "g00gle": "google", "linkedin": "llnkedln", "5ecur3": "secure",
	} {
		if got := string(appendSkeleton(nil, in)); got != want {
			t.Errorf("skeleton(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBrands(t *testing.T) {
	seen := make(map[string]bool)
	for _, b := range brands {
		if b.name == "" || strings.ContainsAny(b.name, ".-") || len(b.domains) == 0 || seen[b.name] {
			t.Errorf("bad brand %+v", b)
		}
		seen[b.name] = true
		for _, d := range b.domains {
			if Registrable(d) != d && !strings.HasPrefix(d, "aws.") {
				t.Errorf("brand %s: %s isn't a registrable domain", b.name, d)
			}
		}
		// Every brand's own domains pass.
		for _, d := range b.domains {
			if why, ok := Typosquat(d); ok {
				t.Errorf("brand %s's own domain flagged: %s", b.name, why)
			}
		}
	}
	for _, w := range riskWords {
		if w != strings.ToLower(w) || strings.ContainsAny(w, ".- ") {
			t.Errorf("bad risk word %q", w)
		}
	}
}

func FuzzTyposquat(f *testing.F) {
	for _, s := range []string{"paypal.com", "paypa1.com", "paypal-login.com", "paypal.com.example.net", "xn--pypal-4ve.com", "a.b.c", "", "-.-", "rnrnrn.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		why, ok := Typosquat(name)
		if ok != (why != "") {
			t.Fatalf("Typosquat(%q) = %q, %v", name, why, ok)
		}
		if ok && !strings.HasPrefix(why, "looks like ") {
			t.Fatalf("Typosquat(%q) gave reason %q", name, why)
		}
		if ok {
			// A brand's own domains are never flagged, so the name can't be
			// under one.
			if _, owned := typo.owned.match(Registrable(name)); owned {
				if _, uc := userContentDomains.match(Registrable(name)); !uc {
					t.Fatalf("Typosquat(%q) flagged a brand's own domain: %s", name, why)
				}
			}
		}
	})
}

func FuzzEditDistance(f *testing.F) {
	f.Add("paypal", "paypla", 2)
	f.Fuzz(func(t *testing.T, a, b string, max int) {
		max = max % 4
		if max < 0 {
			max = -max
		}
		d := editDistance([]byte(a), b, max)
		if d < 0 || d > max+1 {
			t.Fatalf("editDistance(%q, %q, %d) = %d", a, b, max, d)
		}
		// Symmetric, and zero only for equal strings.
		if d2 := editDistance([]byte(b), a, max); d2 != d {
			t.Fatalf("editDistance not symmetric for %q, %q: %d, %d", a, b, d, d2)
		}
		if (d == 0) != (a == b) && len(a) <= maxLabel && len(b) <= maxLabel {
			t.Fatalf("editDistance(%q, %q) = %d", a, b, d)
		}
	})
}

func BenchmarkTyposquat(b *testing.B) {
	for _, name := range []string{"www.example.com", "paypa1.com", "login.paypal.com", "cdn.assets.some-long-legitimate-name.co.uk"} {
		// As the engine calls it, with the registrable domain it has
		// already found.
		reg := Registrable(name)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				typosquat(name, reg)
			}
		})
	}
}
