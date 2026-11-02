package brand

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestAppIcons_Committed checks that the web UI's committed icons are
// exactly what AppIcons draws, so they can't drift from the mark. If it
// fails after a change to the mark, run "go generate ./internal/brand".
//
// The bytes are compared on amd64, where CI runs. Elsewhere, compilers
// may fuse floating-point multiplies and adds, which can tip a
// sub-sample at a shape's edge, so the pixels are compared, each channel
// within a sixteenth of the range.
func TestAppIcons_Committed(t *testing.T) {
	icons, err := AppIcons()
	if err != nil {
		t.Fatal(err)
	}
	if len(icons) != len(iconSpecs) {
		t.Fatalf("%d icons", len(icons))
	}
	for _, icon := range icons {
		committed, err := os.ReadFile(filepath.Join("..", "webui", "static", icon.Name))
		if err != nil {
			t.Fatalf("%v; run go generate ./internal/brand", err)
		}
		if runtime.GOARCH == "amd64" {
			if !bytes.Equal(committed, icon.PNG) {
				t.Errorf("%s differs from what AppIcons draws; run go generate ./internal/brand", icon.Name)
			}
			continue
		}
		a, b := decode(t, committed), decode(t, icon.PNG)
		if a.Bounds() != b.Bounds() {
			t.Fatalf("%s: size %v, want %v", icon.Name, a.Bounds(), b.Bounds())
		}
		for i := range a.Pix {
			if d := int(a.Pix[i]) - int(b.Pix[i]); d > 16 || d < -16 {
				t.Fatalf("%s differs at byte %d; run go generate ./internal/brand", icon.Name, i)
			}
		}
	}
}

func decode(t *testing.T, b []byte) *image.NRGBA {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	n := image.NewNRGBA(img.Bounds())
	draw.Draw(n, n.Bounds(), img, image.Point{}, draw.Src)
	return n
}

// TestAppIcons_Shapes checks each icon's size and what's opaque: the
// maskable and Apple icons fill to the edge, since platforms crop or fill
// them; the maskable one keeps the donut inside the safe zone; the
// others are transparent around it; and the badge is a white silhouette.
func TestAppIcons_Shapes(t *testing.T) {
	icons, err := AppIcons()
	if err != nil {
		t.Fatal(err)
	}
	for i, icon := range icons {
		spec := iconSpecs[i]
		img := decode(t, icon.PNG)
		if img.Bounds().Dx() != spec.size || img.Bounds().Dy() != spec.size {
			t.Errorf("%s is %v", icon.Name, img.Bounds())
		}
		corner := img.NRGBAAt(0, 0)
		center := img.NRGBAAt(spec.size/2, spec.size/2) // the hole
		if spec.background {
			if bg := (color.NRGBA{IconBackground.R, IconBackground.G, IconBackground.B, 255}); corner != bg || center != bg {
				t.Errorf("%s: corner %v, center %v; want the background", icon.Name, corner, center)
			}
		} else if corner.A != 0 || center.A != 0 {
			t.Errorf("%s: corner %v, center %v; want transparent", icon.Name, corner, center)
		}
		if spec.radius*2 >= 1 || (spec.background && spec.name == "icon-maskable-512.png" && spec.radius > 0.4) {
			t.Errorf("%s: radius %v is outside the icon or the safe zone", icon.Name, spec.radius)
		}
		if spec.badge {
			for p := 0; p < len(img.Pix); p += 4 {
				if a := img.Pix[p+3]; a > 0 && (img.Pix[p] != 255 || img.Pix[p+1] != 255 || img.Pix[p+2] != 255) {
					t.Fatalf("%s isn't white", icon.Name)
				}
			}
		}
	}
	again, _ := AppIcons()
	for i := range icons {
		if !bytes.Equal(icons[i].PNG, again[i].PNG) {
			t.Errorf("%s isn't drawn the same twice", icons[i].Name)
		}
	}
}
