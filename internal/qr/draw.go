package qr

import (
	"encoding/xml"
	"fmt"
	"image"
	"image/color"
	"math"
	"strconv"
	"strings"
)

// Style says how [Code.Draw] draws a code.
type Style struct {
	// Paper is the light color, and Ink the dark modules'. Eye and Pupil
	// color the finder patterns' rings and centers. Scanners need each of
	// Ink, Eye, and Pupil to be much darker than Paper.
	Paper, Ink, Eye, Pupil color.RGBA

	// Quiet is the light margin around the code, in modules; the standard
	// asks for 4.
	Quiet int

	// Hole is the radius, in modules, of a circle at the center left
	// light for a logo; see [Code.Hole] for how large it can safely be.
	Hole float64
}

// Draw draws the code as a [Drawing] in style: modules that touch merge
// into rounded runs, finder patterns become rounded squares, and a hole
// is left for a logo, which the caller draws into it.
//
// One unit is one module, and the drawing is Size + 2×Quiet units square.
func (c *Code) Draw(s Style) *Drawing {
	q := float64(s.Quiet)
	d := &Drawing{Side: float64(c.size) + 2*q}
	d.add(shape{kind: rect, x: 0, y: 0, w: d.Side, h: d.Side}, s.Paper)

	finder := func(x, y int) bool {
		n := c.size
		return (x < 7 && y < 7) || (x >= n-7 && y < 7) || (x < 7 && y >= n-7)
	}
	dark := func(x, y int) bool {
		return c.Dark(x, y) && !finder(x, y) && !c.Covers(x, y, s.Hole)
	}

	// Each run of dark modules in a row is one shape. A corner is round
	// where nothing dark continues the run past it, so lone modules are
	// dots and runs are pills, and modules above and below still join.
	const round = 0.5
	corner := func(open bool) float64 {
		if open {
			return round
		}
		return 0
	}
	for y := range c.size {
		for x := 0; x < c.size; {
			if !dark(x, y) {
				x++
				continue
			}
			end := x + 1
			for dark(end, y) {
				end++
			}
			d.add(shape{
				kind: rect, x: float64(x) + q, y: float64(y) + q, w: float64(end - x), h: 1,
				r: [4]float64{
					corner(!dark(x, y-1)), corner(!dark(end-1, y-1)),
					corner(!dark(end-1, y+1)), corner(!dark(x, y+1)),
				},
			}, s.Ink)
			x = end
		}
	}

	// The finder patterns: a 7×7 ring around a 3×3 center. Each is as
	// round as it can be with every module's center still its color: a
	// corner of radius r leaves the corner module's center inside it while
	// (r - ½)√2 ≤ r, so r ≤ ½√2/(√2 - 1), about 1.707; 1.5 leaves a margin.
	corners := [][2]float64{{0, 0}, {float64(c.size - 7), 0}, {0, float64(c.size - 7)}}
	for _, at := range corners {
		d.add(shape{kind: rect, x: at[0] + q, y: at[1] + q, w: 7, h: 7, r: radii(1.5)}, s.Eye)
	}
	for _, at := range corners {
		d.add(shape{kind: rect, x: at[0] + q + 1, y: at[1] + q + 1, w: 5, h: 5, r: radii(1.5)}, s.Paper)
	}
	for _, at := range corners {
		d.add(shape{kind: rect, x: at[0] + q + 2, y: at[1] + q + 2, w: 3, h: 3, r: radii(1)}, s.Pupil)
	}
	return d
}

func radii(r float64) [4]float64 { return [4]float64{r, r, r, r} }

// A Drawing is a picture made of simple shapes, painted in order, that
// renders the same as SVG and as an image: the image is how tests check
// that what people see still scans.
type Drawing struct {
	// Side is the drawing's width and height, in units.
	Side float64

	shapes []shape
}

type kind int

const (
	rect    kind = iota // a rectangle, with rounded corners
	ring                // an annulus; a disc if its inner radius is 0
	capsule             // a line segment with round ends
)

type shape struct {
	kind   kind
	fill   color.RGBA
	x, y   float64    // rect: top left; ring: center; capsule: one end
	w, h   float64    // rect: size; capsule: the other end
	r      [4]float64 // rect: corner radii, clockwise from top left
	r1, r2 float64    // ring: inner and outer radius; capsule: r2 is its radius
}

func (d *Drawing) add(s shape, fill color.RGBA) {
	s.fill = fill
	d.shapes = append(d.shapes, s)
}

// Circle draws a disc.
func (d *Drawing) Circle(cx, cy, r float64, fill color.RGBA) {
	d.add(shape{kind: ring, x: cx, y: cy, r2: r}, fill)
}

// Ring draws an annulus between radii inner and outer.
func (d *Drawing) Ring(cx, cy, inner, outer float64, fill color.RGBA) {
	d.add(shape{kind: ring, x: cx, y: cy, r1: inner, r2: outer}, fill)
}

// Capsule draws a line from (x1, y1) to (x2, y2), r thick on each side,
// with round ends.
func (d *Drawing) Capsule(x1, y1, x2, y2, r float64, fill color.RGBA) {
	d.add(shape{kind: capsule, x: x1, y: y1, w: x2, h: y2, r2: r}, fill)
}

// SVG returns the drawing as a standalone SVG image, labelled label for
// assistive technology.
func (d *Drawing) SVG(label string) string {
	var b strings.Builder
	side := num(d.Side)
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" role="img" aria-label="%s">`, side, side, escape(label))

	// Consecutive shapes of one color are one path; rings are their own,
	// since their holes need the even-odd rule.
	var path strings.Builder
	var fill color.RGBA
	flush := func() {
		if path.Len() > 0 {
			fmt.Fprintf(&b, `<path fill="%s" d="%s"/>`, hex(fill), path.String())
			path.Reset()
		}
	}
	for _, s := range d.shapes {
		if s.kind == ring && s.r1 > 0 {
			flush()
			fmt.Fprintf(&b, `<path fill="%s" fill-rule="evenodd" d="%s%s"/>`, hex(s.fill), circlePath(s.x, s.y, s.r2), circlePath(s.x, s.y, s.r1))
			continue
		}
		if s.fill != fill {
			flush()
			fill = s.fill
		}
		switch s.kind {
		case rect:
			rectPath(&path, s)
		case ring:
			path.WriteString(circlePath(s.x, s.y, s.r2))
		case capsule:
			capsulePath(&path, s)
		}
	}
	flush()
	b.WriteString("</svg>")
	return b.String()
}

// rectPath writes a rounded rectangle, clockwise from its top left.
func rectPath(b *strings.Builder, s shape) {
	tl, tr, br, bl := s.r[0], s.r[1], s.r[2], s.r[3]
	arc := func(r, dx, dy float64) {
		if r > 0 {
			fmt.Fprintf(b, "a%s %s 0 0 1 %s %s", num(r), num(r), num(dx), num(dy))
		}
	}
	fmt.Fprintf(b, "M%s %s", num(s.x+tl), num(s.y))
	if l := s.w - tl - tr; l != 0 {
		fmt.Fprintf(b, "h%s", num(l))
	}
	arc(tr, tr, tr)
	if l := s.h - tr - br; l != 0 {
		fmt.Fprintf(b, "v%s", num(l))
	}
	arc(br, -br, br)
	if l := s.w - br - bl; l != 0 {
		fmt.Fprintf(b, "h%s", num(-l))
	}
	arc(bl, -bl, -bl)
	if l := s.h - bl - tl; l != 0 {
		fmt.Fprintf(b, "v%s", num(-l))
	}
	arc(tl, tl, -tl)
	b.WriteString("z")
}

func circlePath(cx, cy, r float64) string {
	return fmt.Sprintf("M%s %sa%s %s 0 0 1 0 %sa%s %s 0 0 1 0 %sz",
		num(cx), num(cy-r), num(r), num(r), num(2*r), num(r), num(r), num(-2*r))
}

func capsulePath(b *strings.Builder, s shape) {
	dx, dy := s.w-s.x, s.h-s.y
	l := math.Hypot(dx, dy)
	if l == 0 {
		b.WriteString(circlePath(s.x, s.y, s.r2))
		return
	}
	nx, ny := -dy/l*s.r2, dx/l*s.r2
	r := num(s.r2)
	fmt.Fprintf(b, "M%s %sL%s %sA%s %s 0 0 1 %s %sL%s %sA%s %s 0 0 1 %s %sz",
		num(s.x+nx), num(s.y+ny), num(s.w+nx), num(s.h+ny),
		r, r, num(s.w-nx), num(s.h-ny), num(s.x-nx), num(s.y-ny),
		r, r, num(s.x+nx), num(s.y+ny))
}

// num formats v briefly: to three decimals, without a leading zero.
func num(v float64) string {
	s := strconv.FormatFloat(math.Round(v*1000)/1000, 'f', -1, 64)
	switch {
	case strings.HasPrefix(s, "0."):
		return s[1:]
	case strings.HasPrefix(s, "-0."):
		return "-" + s[2:]
	case s == "-0":
		return "0"
	}
	return s
}

func hex(c color.RGBA) string { return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B) }

// escape escapes s for an XML attribute value. Characters XML can't
// hold, such as control characters and invalid UTF-8, become U+FFFD, so
// any label gives a well-formed image.
func escape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s)) // writes to a strings.Builder don't fail
	return b.String()
}

// Image renders the drawing at scale pixels per unit, antialiased.
func (d *Drawing) Image(scale int) *image.RGBA {
	const ss = 4 // samples per pixel on each axis
	n := int(math.Ceil(d.Side * float64(scale)))
	sn := n * ss
	unit := float64(scale * ss)
	buf := make([]color.RGBA, sn*sn)
	for _, s := range d.shapes {
		x0, y0, x1, y1 := s.bounds()
		for py := max(int(y0*unit), 0); py < min(int(math.Ceil(y1*unit)), sn); py++ {
			for px := max(int(x0*unit), 0); px < min(int(math.Ceil(x1*unit)), sn); px++ {
				if s.contains((float64(px)+0.5)/unit, (float64(py)+0.5)/unit) {
					buf[py*sn+px] = s.fill
				}
			}
		}
	}
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := range n {
		for x := range n {
			var r, g, b, a int
			for j := range ss {
				for i := range ss {
					c := buf[(y*ss+j)*sn+x*ss+i]
					r, g, b, a = r+int(c.R), g+int(c.G), b+int(c.B), a+int(c.A)
				}
			}
			const k = ss * ss
			img.SetRGBA(x, y, color.RGBA{uint8(r / k), uint8(g / k), uint8(b / k), uint8(a / k)})
		}
	}
	return img
}

func (s shape) bounds() (x0, y0, x1, y1 float64) {
	switch s.kind {
	case rect:
		return s.x, s.y, s.x + s.w, s.y + s.h
	case ring:
		return s.x - s.r2, s.y - s.r2, s.x + s.r2, s.y + s.r2
	default:
		return min(s.x, s.w) - s.r2, min(s.y, s.h) - s.r2, max(s.x, s.w) + s.r2, max(s.y, s.h) + s.r2
	}
}

func (s shape) contains(px, py float64) bool {
	switch s.kind {
	case rect:
		if px < s.x || py < s.y || px > s.x+s.w || py > s.y+s.h {
			return false
		}
		// Corner centers, clockwise from top left.
		cs := [4][2]float64{
			{s.x + s.r[0], s.y + s.r[0]},
			{s.x + s.w - s.r[1], s.y + s.r[1]},
			{s.x + s.w - s.r[2], s.y + s.h - s.r[2]},
			{s.x + s.r[3], s.y + s.h - s.r[3]},
		}
		for i, c := range cs {
			r := s.r[i]
			if r <= 0 {
				continue
			}
			left, top := i == 0 || i == 3, i < 2
			outX := (left && px < c[0]) || (!left && px > c[0])
			outY := (top && py < c[1]) || (!top && py > c[1])
			if outX && outY && math.Hypot(px-c[0], py-c[1]) > r {
				return false
			}
		}
		return true
	case ring:
		d := math.Hypot(px-s.x, py-s.y)
		return d <= s.r2 && d >= s.r1
	default:
		dx, dy := s.w-s.x, s.h-s.y
		t := 0.0
		if l2 := dx*dx + dy*dy; l2 > 0 {
			t = min(max(((px-s.x)*dx+(py-s.y)*dy)/l2, 0), 1)
		}
		return math.Hypot(px-(s.x+t*dx), py-(s.y+t*dy)) <= s.r2
	}
}
