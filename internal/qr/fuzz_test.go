package qr

import (
	"bytes"
	"encoding/xml"
	"errors"
	"image/color"
	"testing"
)

// FuzzEncode encodes arbitrary data at every level: it must never panic;
// it must fail only for data too long for version 10; and a code must be
// 17 + 4×version modules on a side, with a finder pattern in each of
// three corners, deterministic for its mask, and drawn as well-formed SVG.
func FuzzEncode(f *testing.F) {
	f.Add([]byte("https://dns.example.com/setup/RfcDwNWF3WMikylWanaHcg"), uint8(1))
	f.Add([]byte{}, uint8(0))
	f.Add(bytes.Repeat([]byte{0xff}, 300), uint8(3))
	f.Add([]byte("<svg>&\"'"), uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, l uint8) {
		level := Level(l % 4)
		c, err := Encode(data, level)
		if err != nil {
			if !errors.Is(err, ErrTooLong) || len(data) <= capacity(MaxVersion, level) {
				t.Fatalf("Encode(%d bytes, %v) = %v", len(data), level, err)
			}
			return
		}
		if len(data) > capacity(c.Version, level) || c.Version > 1 && len(data) <= capacity(c.Version-1, level) {
			t.Fatalf("%d bytes at level %v got version %d, not the smallest that fits", len(data), level, c.Version)
		}
		if c.Size() != 17+4*c.Version || c.Mask < 0 || c.Mask > 7 {
			t.Fatalf("version %d, size %d, mask %d", c.Version, c.Size(), c.Mask)
		}
		for _, corner := range [][2]int{{0, 0}, {c.Size() - 7, 0}, {0, c.Size() - 7}} {
			for y := range 7 {
				for x := range 7 {
					ring := max(abs(x-3), abs(y-3))
					if want := ring != 2; c.Dark(corner[0]+x, corner[1]+y) != want {
						t.Fatalf("finder pattern at %v is broken at (%d, %d)", corner, x, y)
					}
				}
			}
		}
		again, _ := EncodeMask(data, level, c.Version, c.Mask)
		for y := range c.Size() {
			for x := range c.Size() {
				if again.Dark(x, y) != c.Dark(x, y) {
					t.Fatal("encoding isn't deterministic")
				}
			}
		}
		svg := c.Draw(Style{Ink: color.RGBA{A: 255}, Eye: color.RGBA{A: 255}, Pupil: color.RGBA{A: 255}, Paper: color.RGBA{255, 255, 255, 255}, Quiet: 4, Hole: c.Hole(0.5)}).SVG(string(data))
		if err := xml.Unmarshal([]byte(svg), new(struct{})); err != nil {
			t.Fatalf("SVG isn't well-formed: %v", err)
		}
	})
}
