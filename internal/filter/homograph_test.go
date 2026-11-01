package filter

import (
	"testing"

	"golang.org/x/net/idna"
)

// puny encodes a Unicode name as an A-label name.
func puny(t *testing.T, name string) string {
	t.Helper()
	a, err := idna.ToASCII(name)
	if err != nil {
		t.Fatalf("encoding %q: %v", name, err)
	}
	return a
}

func TestHomograph(t *testing.T) {
	for _, tt := range []struct {
		name    string
		unicode bool // encode name as Punycode first
		want    bool
	}{
		{name: "example.com"},
		{name: "apple.com"},
		{name: "аpple.com", unicode: true, want: true},      // Cyrillic а, then Latin
		{name: "аррӏе.com", unicode: true, want: true},      // all Cyrillic look-alikes
		{name: "раураl.com", unicode: true, want: true},     // all Cyrillic look-alikes
		{name: "аррӏе.ru", unicode: true},                   // all Cyrillic, under a Cyrillic ccTLD
		{name: "пример.рф", unicode: true},                  // ordinary Cyrillic name and TLD
		{name: "москва.com", unicode: true},                 // Cyrillic, with letters that don't look Latin
		{name: "münchen.de", unicode: true},                 // Latin with diacritics
		{name: "東京.jp", unicode: true},                      // Han
		{name: "ドメイン名例.jp", unicode: true},                  // Katakana and Han
		{name: "abcカタカナ.jp", unicode: true},                 // Latin and Katakana: allowed together
		{name: "한국abc.kr", unicode: true},                   // Latin and Hangul
		{name: "ɡoogle.com", unicode: true, want: true},     // U+0261 script g
		{name: "gооgle.com", unicode: true, want: true},     // Latin with Cyrillic о
		{name: "xn--zzzzzzzzzzzzzzzzzzzzz.com", want: true}, // invalid Punycode
		{name: "xn--a.com", want: true},                     // invalid Punycode
		{name: "paypal.xn--p1ai"},                           // ASCII label under an IDN TLD
		{name: "ελληνικά.gr", unicode: true},                // Greek, under .gr
		{name: "ορεν.com", unicode: true, want: true},       // all-Greek look-alike of "open"
		{name: "a‍b.com", unicode: false},                   // not Punycode: plain names aren't checked
	} {
		t.Run(tt.name, func(t *testing.T) {
			name := tt.name
			if tt.unicode {
				name = puny(t, name)
			}
			reason, got := Homograph(name)
			if got != tt.want {
				t.Errorf("Homograph(%q) = %v (%s), want %v", name, got, reason, tt.want)
			}
			if got && reason == "" {
				t.Error("flagged without a reason")
			}
		})
	}
}

func TestHomograph_InvisibleCharacter(t *testing.T) {
	// A zero-width joiner, encoded directly with Punycode since IDNA
	// refuses to encode it.
	label, err := idna.Punycode.ToASCII("pay‍pal")
	if err != nil {
		t.Fatal(err)
	}
	if _, got := Homograph(label + ".com"); !got {
		t.Errorf("Homograph(%q) = false, want true for a zero-width joiner", label)
	}
}

func TestRegistrable(t *testing.T) {
	for name, want := range map[string]string{
		"www.example.com.":     "example.com",
		"example.com":          "example.com",
		"a.b.example.co.uk":    "example.co.uk",
		"user.github.io":       "github.io", // private suffixes are ignored
		"com":                  "",
		"localhost":            "",
		"WWW.Example.COM":      "example.com",
		"x.y.unknown-tld-zzzz": "",
	} {
		if got := Registrable(name); got != want {
			t.Errorf("Registrable(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestIsLocal(t *testing.T) {
	for name, want := range map[string]bool{
		"nas":                       true,
		"printer.lan":               true,
		"nas.home.arpa.":            true,
		"router.local":              true,
		"1.1.168.192.in-addr.arpa.": true,
		"example.com":               false,
		"home.example.com":          false,
		"localhost":                 true,
	} {
		if got := IsLocal(name); got != want {
			t.Errorf("IsLocal(%q) = %v, want %v", name, got, want)
		}
	}
}
