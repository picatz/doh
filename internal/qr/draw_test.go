package qr

import (
	"image/color"
	"math"
	"strings"
	"testing"
)

var testStyle = Style{
	Paper: color.RGBA{255, 255, 255, 255},
	Ink:   color.RGBA{0, 0, 0, 255},
	Eye:   color.RGBA{0, 0, 255, 255},
	Pupil: color.RGBA{255, 0, 0, 255},
	Quiet: 4,
}

// TestDraw_ModulesKeepTheirColor checks the drawing against the code,
// module by module, at the center of each module, where readers sample:
// rounding, the finders' style, and the hole change nothing else.
func TestDraw_ModulesKeepTheirColor(t *testing.T) {
	for v := 1; v <= MaxVersion; v++ {
		for _, hole := range []bool{false, true} {
			c, err := EncodeVersion([]byte("https://dns.example.com/setup/RfcDwNWF3WMikylWanaHcg"[:min(40, capacity(v, Q))]), Q, v)
			if err != nil {
				t.Fatal(err)
			}
			s := testStyle
			if hole {
				s.Hole = c.Hole(0.5)
			}
			const scale = 9 // odd, so a pixel is centered on each module
			img := c.Draw(s).Image(scale)
			if b := img.Bounds(); b.Dx() != (c.Size()+8)*scale {
				t.Fatalf("version %d: image %v, want %d px", v, b, (c.Size()+8)*scale)
			}
			for y := -4; y < c.Size()+4; y++ {
				for x := -4; x < c.Size()+4; x++ {
					got := img.RGBAAt((x+4)*scale+scale/2, (y+4)*scale+scale/2)
					want := s.Paper
					switch {
					case c.Covers(x, y, s.Hole):
					case finderRing(c, x, y):
						want = s.Eye
					case finderPupil(c, x, y):
						want = s.Pupil
					case c.Dark(x, y):
						want = s.Ink
					}
					if got != want {
						t.Fatalf("version %d, hole %v: module (%d, %d) is %v, want %v", v, hole, x, y, got, want)
					}
				}
			}
		}
	}
}

// finderRing and finderPupil report whether a module is in a finder
// pattern's outer ring, or its 3×3 center.
func finderRing(c *Code, x, y int) bool {
	ox, oy, ok := finderAt(c, x, y)
	return ok && (ox == 0 || oy == 0 || ox == 6 || oy == 6)
}

func finderPupil(c *Code, x, y int) bool {
	ox, oy, ok := finderAt(c, x, y)
	return ok && ox >= 2 && ox <= 4 && oy >= 2 && oy <= 4
}

func finderAt(c *Code, x, y int) (int, int, bool) {
	n := c.Size()
	for _, at := range [][2]int{{0, 0}, {n - 7, 0}, {0, n - 7}} {
		if ox, oy := x-at[0], y-at[1]; ox >= 0 && oy >= 0 && ox < 7 && oy < 7 {
			return ox, oy, true
		}
	}
	return 0, 0, false
}

func TestHole(t *testing.T) {
	for v := 1; v <= MaxVersion; v++ {
		c, err := EncodeVersion([]byte("x"), H, v)
		if err != nil {
			t.Fatal(err)
		}
		r := c.Hole(0.5)
		if v >= 7 && r != 0 {
			t.Errorf("version %d: hole %v over the central alignment pattern", v, r)
		}
		if v < 7 && r == 0 {
			t.Errorf("version %d: no hole", v)
		}
		// No function module is cleared, and each block keeps half its
		// correction.
		wrong := map[int16]bool{}
		perBlock := map[int8]int{}
		for y := range c.Size() {
			for x := range c.Size() {
				if !c.Covers(x, y, r) {
					continue
				}
				i := y*c.Size() + x
				if c.function[i] {
					t.Errorf("version %d: hole clears function module (%d, %d)", v, x, y)
				}
				if cw := c.codeword[i]; cw >= 0 && !wrong[cw] {
					wrong[cw] = true
					perBlock[c.blockOf[cw]]++
				}
			}
		}
		for b, n := range perBlock {
			if n > c.ec/4 {
				t.Errorf("version %d: block %d loses %d codewords of %d correctable", v, b, n, c.ec/2)
			}
		}
		if c.Hole(0) != 0 && v < 7 {
			// A budget of nothing leaves room only for remainder bits.
			if r0 := c.Hole(0); r0 >= r {
				t.Errorf("version %d: a budget of 0 allows %v, as much as half's %v", v, r0, r)
			}
		}
	}
}

func TestCovers(t *testing.T) {
	c, _ := EncodeVersion([]byte("x"), M, 1) // 21 modules, center 10.5
	for _, tt := range []struct {
		x, y int
		r    float64
		want bool
	}{
		{10, 10, 0.1, true},  // the center module
		{10, 10, 0, false},   // no hole
		{11, 10, 0.4, false}, // its edge is 0.5 away
		{11, 10, 0.6, true},
		{12, 12, 1.5*math.Sqrt2 - 0.01, false}, // its corner is 1.5√2 away
		{12, 12, 1.5*math.Sqrt2 + 0.01, true},
	} {
		if got := c.Covers(tt.x, tt.y, tt.r); got != tt.want {
			t.Errorf("Covers(%d, %d, %v) = %v, want %v", tt.x, tt.y, tt.r, got, tt.want)
		}
	}
}

func TestDrawing_SVG(t *testing.T) {
	c, _ := EncodeVersion([]byte("doh"), M, 1)
	d := c.Draw(testStyle)
	d.Ring(14.5, 14.5, 1, 2, color.RGBA{1, 2, 3, 255})
	d.Capsule(1, 1, 3, 1, 0.5, color.RGBA{4, 5, 6, 255})
	svg := d.SVG(`a "label" & <more>`)
	for _, want := range []string{
		`viewBox="0 0 29 29"`,
		`role="img" aria-label="a &#34;label&#34; &amp; &lt;more&gt;"`,
		`fill="#0000ff"`, `fill="#ff0000"`, `fill="#000000"`,
		`fill="#010203" fill-rule="evenodd"`,
		`fill="#040506"`,
	} {
		if !strings.Contains(svg, want) {
			t.Errorf("SVG lacks %s", want)
		}
	}
	for _, bad := range []string{"<script", "href", "NaN", "Inf"} {
		if strings.Contains(svg, bad) {
			t.Errorf("SVG contains %q", bad)
		}
	}
}

func TestNum(t *testing.T) {
	for v, want := range map[float64]string{0: "0", 0.5: ".5", -0.5: "-.5", 1.23456: "1.235", -0.0001: "0", 12: "12"} {
		if got := num(v); got != want {
			t.Errorf("num(%v) = %q, want %q", v, got, want)
		}
	}
}
