package brand

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	"github.com/picatz/doh/internal/qr"
)

//go:generate go run ./genicons ../webui/static

// IconBackground is the app icons' background where they need one: the
// web UI's dark page color (--bg in dark mode), so the donut's glaze and
// sprinkles stand out as they do in the UI.
var IconBackground = color.RGBA{0x0f, 0x0f, 0x13, 0xff}

// Icon is one of the web UI's app icons.
type Icon struct {
	// Name is its file name in the UI's static files, such as
	// "icon-192.png".
	Name string

	// Size is its width and height, in pixels.
	Size int

	// PNG is the icon, encoded.
	PNG []byte
}

// iconSpec is how one icon is drawn.
type iconSpec struct {
	name string
	size int

	// radius is the donut's, as a fraction of the size: from its center to
	// its farthest edge.
	radius float64

	// background fills the icon, or, if false, it's transparent.
	background bool

	// badge draws the donut as a white silhouette, for Android's status
	// bar, which shows only an icon's alpha.
	badge bool
}

// iconSpecs are the web UI's icons:
//
//   - icon-192 and icon-512, for any purpose: the donut alone, filling the
//     icon, on transparency.
//   - icon-maskable-512, which platforms crop to their own shape: the
//     donut within the safe zone, a circle of 40% of the size around the
//     center, on a background to the edges.
//   - apple-touch-icon, for iOS home screens, which fill transparency with
//     black: on the background, with room for iOS's rounded corners.
//   - badge-96, for notifications' small icon: a white silhouette.
var iconSpecs = []iconSpec{
	{name: "icon-192.png", size: 192, radius: 0.46},
	{name: "icon-512.png", size: 512, radius: 0.46},
	{name: "icon-maskable-512.png", size: 512, radius: 0.33, background: true},
	{name: "apple-touch-icon.png", size: 180, radius: 0.37, background: true},
	{name: "badge-96.png", size: 96, radius: 0.46, badge: true},
}

// AppIcons draws the web UI's app icons, as PNGs. They're the same, to
// the byte, every time: "go generate" writes them to the UI's static
// files, and a test checks they haven't drifted.
func AppIcons() ([]Icon, error) {
	icons := make([]Icon, 0, len(iconSpecs))
	for _, spec := range iconSpecs {
		img := spec.draw()
		var b bytes.Buffer
		enc := png.Encoder{CompressionLevel: png.BestCompression}
		if err := enc.Encode(&b, img); err != nil {
			return nil, err
		}
		icons = append(icons, Icon{Name: spec.name, Size: spec.size, PNG: b.Bytes()})
	}
	return icons, nil
}

// draw draws the icon.
func (spec iconSpec) draw() *image.NRGBA {
	size := float64(spec.size)
	d := &qr.Drawing{Side: size}
	mid, r := size/2, spec.radius*size
	if spec.badge {
		donut(d, mid, mid, r, Sprinkle, Sprinkle, nil)
	} else {
		Donut(d, mid, mid, r)
	}
	art := d.Image(1)

	out := image.NewNRGBA(image.Rect(0, 0, spec.size, spec.size))
	if spec.background {
		draw.Draw(out, out.Bounds(), image.NewUniform(IconBackground), image.Point{}, draw.Src)
	}
	draw.Draw(out, out.Bounds(), art, image.Point{}, draw.Over)
	return out
}
