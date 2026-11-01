package plist

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestMarshal(t *testing.T) {
	got := string(Marshal(Dict{
		{"Name", String(`Kids & <friends>`)},
		{"Version", Integer(1)},
		{"Removable", Bool(false)},
		{"Items", Array{String("a"), Bool(true)}},
	}))

	want := `<dict>
	<key>Name</key>
	<string>Kids &amp; &lt;friends&gt;</string>
	<key>Version</key>
	<integer>1</integer>
	<key>Removable</key>
	<false/>
	<key>Items</key>
	<array>
		<string>a</string>
		<true/>
	</array>
</dict>
</plist>
`
	if !strings.HasPrefix(got, header) || got[len(header):] != want {
		t.Errorf("Marshal =\n%s", got)
	}
}

func TestMarshal_WellFormed(t *testing.T) {
	// Hostile strings can't break out of their elements.
	b := Marshal(Dict{{"</key><key>x", String("]]></string><true/><string>")}})

	d := xml.NewDecoder(strings.NewReader(string(b)))
	d.Strict = true
	var strs []string
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		if c, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(c)) != "" {
			strs = append(strs, string(c))
		}
	}
	if len(strs) != 2 || strs[0] != "</key><key>x" || strs[1] != "]]></string><true/><string>" {
		t.Errorf("decoded %q", strs)
	}
	if strings.Count(string(b), "<true/>") != 0 {
		t.Error("an injected element survived escaping")
	}
}
