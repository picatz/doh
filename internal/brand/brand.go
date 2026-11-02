// Package brand draws doh's mark, a glazed donut, and the things that
// carry it, such as the QR codes that set up devices.
package brand

import (
	"image/color"
	"math"

	"github.com/picatz/doh/internal/qr"
)

// doh's colors. The donut's are the icon's; the QR code's dark colors
// stay far darker than Paper, so cameras read them in any light.
var (
	Dough    = color.RGBA{0xe8, 0xb4, 0x6f, 0xff}
	Glaze    = color.RGBA{0xd6, 0x33, 0x6c, 0xff}
	Sprinkle = color.RGBA{0xff, 0xff, 0xff, 0xff}

	Paper    = color.RGBA{0xff, 0xff, 0xff, 0xff}
	Ink      = color.RGBA{0x2a, 0x0e, 0x1c, 0xff} // a deep plum, nearly black
	GlazeInk = color.RGBA{0xa0, 0x1d, 0x4b, 0xff} // the glaze, darkened to scan
)

// Donut draws the mark centered at (cx, cy), r units from its center to
// its farthest edge: the icon's dough and glaze rings, with sprinkles.
func Donut(d *qr.Drawing, cx, cy, r float64) {
	// The icon is drawn on a 32-unit grid: dough a ring of radius 10 and
	// width 9 around (16, 16.8), glaze one of width 8 around (16, 15.4).
	// Its extent is 1.4 to 31.3 down and 1.5 to 30.5 across, so its
	// middle is (16, 16.35) and its half-height 14.95.
	s := r / 14.95
	at := func(x, y float64) (float64, float64) { return cx + (x-16)*s, cy + (y-16.35)*s }

	x, y := at(16, 16.8)
	d.Ring(x, y, 5.5*s, 14.5*s, Dough)
	gx, gy := at(16, 15.4)
	d.Ring(gx, gy, 6*s, 14*s, Glaze)

	// Sprinkles around the glaze, each at its own tilt, like the ones the
	// Overview's ring scatters for blocked queries.
	for _, sp := range sprinkles {
		a := sp.angle * math.Pi / 180
		mx, my := gx+math.Cos(a)*sp.radius*s, gy+math.Sin(a)*sp.radius*s
		t := (sp.angle + sp.tilt) * math.Pi / 180
		hx, hy := math.Cos(t)*1.6*s, math.Sin(t)*1.6*s
		d.Capsule(mx-hx, my-hy, mx+hx, my+hy, 0.62*s, Sprinkle)
	}
}

// sprinkles are where the donut's sprinkles go: an angle around the
// glaze, clockwise from three o'clock, a distance from its center, and a
// tilt from the tangent, all in the icon's units.
var sprinkles = []struct{ angle, radius, tilt float64 }{
	{-150, 10.2, 60}, {-108, 9.4, -25}, {-62, 10.6, 40},
	{-18, 9.6, -55}, {28, 10.4, 20}, {150, 9.8, -35}, {196, 10.6, 75},
}

// QR draws data, such as a setup link, as a QR code in doh's colors, with
// the donut in the middle when there's room for it.
//
// The donut's hole in the code is no larger than [qr.Code.Hole] allows
// with a budget of half: whatever it covers, each block of the code can
// still correct as many wrong codewords as one at half its level. Data
// too long for that is drawn without the donut, at level M.
func QR(data []byte) (*qr.Drawing, error) {
	style := qr.Style{Paper: Paper, Ink: Ink, Eye: GlazeInk, Pupil: Ink, Quiet: 4}

	// Version 6 is the largest without an alignment pattern at the
	// center, and leaves the most room: about a third of its width at H.
	for _, level := range []qr.Level{qr.H, qr.Q} {
		c, err := qr.EncodeVersion(data, level, 6)
		if err != nil {
			continue
		}
		hole := c.Hole(0.5)
		if 2*hole < 0.25*float64(c.Size()) {
			continue
		}
		style.Hole = hole
		d := c.Draw(style)
		mid := d.Side / 2
		Donut(d, mid, mid, hole-0.75)
		return d, nil
	}

	c, err := qr.Encode(data, qr.M)
	if err != nil {
		return nil, err
	}
	return c.Draw(style), nil
}
