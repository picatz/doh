package webui

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// tokens returns the color custom properties declared in the first CSS
// block of css whose selector is selector.
func tokens(t *testing.T, css, selector string) map[string]string {
	t.Helper()
	i := strings.Index(css, selector+" {")
	if i < 0 {
		t.Fatalf("no %q block in app.css", selector)
	}
	body := css[i+len(selector)+2:]
	body = body[:strings.Index(body, "}")]
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\b`).FindAllStringSubmatch(body, -1) {
		out[m[1]] = strings.ToLower(m[2])
	}
	return out
}

// luminance returns the relative luminance of a #rrggbb color, as WCAG
// defines it.
//
// [WCAG 2.2, relative luminance]: https://www.w3.org/TR/WCAG22/#dfn-relative-luminance
func luminance(hex string) float64 {
	channel := func(s string) float64 {
		v, _ := strconv.ParseUint(s, 16, 8)
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*channel(hex[1:3]) + 0.7152*channel(hex[3:5]) + 0.0722*channel(hex[5:7])
}

// contrast returns the WCAG contrast ratio of two colors.
//
// [WCAG 2.2, contrast ratio]: https://www.w3.org/TR/WCAG22/#dfn-contrast-ratio
func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// TestContrast checks that the UI's color tokens meet WCAG 2.2 AA in both
// themes: 4.5:1 for text (1.4.3), and 3:1 for what marks a control or its
// state (1.4.11), so a palette change can't quietly make doh harder to
// read.
func TestContrast(t *testing.T) {
	css := readStatic(t, "app.css")
	light := tokens(t, css, ":root")
	dark := tokens(t, css, ":root[data-theme=dark]")

	// The dark theme is declared twice, for the system's preference and
	// for someone's choice; they must agree.
	system := tokens(t, css, "  :root:not([data-theme=light])")
	if fmt.Sprint(system) != fmt.Sprint(dark) {
		t.Errorf("the system dark theme and the chosen one differ:\n%v\n%v", system, dark)
	}

	const text, ui = 4.5, 3.0
	pairs := []struct {
		fg, bg string
		min    float64
		what   string
	}{
		{"text", "bg", text, "body text"},
		{"text", "surface", text, "text on cards"},
		{"text", "surface-2", text, "text on raised surfaces"},
		{"text", "surface-3", text, "text on hovered surfaces"},
		{"muted", "bg", text, "secondary text"},
		{"muted", "surface", text, "secondary text on cards"},
		{"muted", "surface-2", text, "secondary text on raised surfaces"},
		{"glaze-ink", "surface", text, "links"},
		{"glaze-ink", "bg", text, "links on the page"},
		{"glaze-ink", "glaze-soft", text, "the current place, such as the selected view"},
		{"accent-text", "glaze", text, "primary buttons"},
		{"accent-text", "glaze-strong", text, "primary buttons under the pointer"},
		{"glaze-ink", "surface-2", text, "pink text on raised surfaces"},
		{"ok", "ok-bg", text, "good news"},
		{"bad", "bad-bg", text, "bad news"},
		{"warn", "warn-bg", text, "warnings"},
		{"info", "info-bg", text, "notes"},
		{"ok", "surface", text, "good news on cards"},
		{"bad", "surface", text, "bad news on cards"},
		{"warn", "surface", text, "warnings on cards"},
		{"glaze", "surface", ui, "focus rings and switches that are on"},
		{"glaze", "bg", ui, "the glaze on the page"},
		{"field-border", "surface", ui, "the edges of fields"},
		{"field-border", "surface-2", ui, "the edges of fields on raised surfaces"},
		{"field-border", "bg", ui, "the edges of fields on the page"},
	}
	for theme, c := range map[string]map[string]string{"light": light, "dark": dark} {
		for _, p := range pairs {
			fg, bg := c[p.fg], c[p.bg]
			if fg == "" || bg == "" {
				t.Errorf("%s: --%s or --%s isn't a color", theme, p.fg, p.bg)
				continue
			}
			if r := contrast(fg, bg); r < p.min {
				t.Errorf("%s: %s (--%s %s on --%s %s) is %.2f:1, want at least %.1f:1", theme, p.what, p.fg, fg, p.bg, bg, r, p.min)
			}
		}
	}
}

func TestContrastMath(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want float64
	}{
		{"#000000", "#ffffff", 21},
		{"#ffffff", "#ffffff", 1},
		{"#777777", "#ffffff", 4.48},
	} {
		if got := contrast(tt.a, tt.b); math.Abs(got-tt.want) > 0.01 {
			t.Errorf("contrast(%s, %s) = %.2f, want %.2f", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestIndex_ControlsHaveNames checks that every button, input, select,
// and textarea in the page has a name assistive technology can say: its
// text, a label, or an ARIA label (WCAG 4.1.2).
func TestIndex_ControlsHaveNames(t *testing.T) {
	index := readStatic(t, "index.html")
	labelled := map[string]bool{}
	for _, m := range regexp.MustCompile(`<label[^>]*\sfor="([^"]+)"`).FindAllStringSubmatch(index, -1) {
		labelled[m[1]] = true
	}
	tags := regexp.MustCompile(`(?s)<(button|input|select|textarea)\b([^>]*)>`)
	for _, loc := range tags.FindAllStringSubmatchIndex(index, -1) {
		tag, attrs := index[loc[2]:loc[3]], index[loc[4]:loc[5]]
		attr := func(name string) string {
			m := regexp.MustCompile(`\s` + name + `="([^"]*)"`).FindStringSubmatch(attrs)
			if m == nil {
				return ""
			}
			return m[1]
		}
		if attr("type") == "hidden" || strings.Contains(attrs, "visually-hidden") && tag == "button" && attr("type") == "submit" {
			continue
		}
		if attr("aria-label") != "" || attr("aria-labelledby") != "" || (attr("id") != "" && labelled[attr("id")]) {
			continue
		}
		// Inside a <label>: the nearest unclosed label before it.
		before := index[:loc[0]]
		if strings.LastIndex(before, "<label") > strings.LastIndex(before, "</label>") {
			continue
		}
		if tag == "button" {
			end := strings.Index(index[loc[1]:], "</button>")
			inner := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(index[loc[1]:loc[1]+end], "")
			if strings.TrimSpace(inner) != "" {
				continue
			}
		}
		t.Errorf("<%s%s> has no accessible name", tag, attrs)
	}
}
