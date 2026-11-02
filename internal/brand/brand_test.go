package brand

import (
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/qr"
)

// setupURL returns a setup link like the server's, for a host name of n
// characters.
func setupURL(n int) string {
	host := strings.Repeat("h", max(n-4, 1)) + ".lan"
	return "https://" + host + "/setup/RfcDwNWF3WMikylWanaHcg"
}

func writePNG(t *testing.T, img image.Image, name string) {
	t.Helper()
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

// TestQR_DecodesWithZBar checks that the branded code, donut and all, as
// people see it, reads back with an independent decoder, ZBar, for setup
// links of every length the server makes, at sizes as small as a phone
// screen draws it.
func TestQR_DecodesWithZBar(t *testing.T) {
	zbar, err := exec.LookPath("zbarimg")
	if err != nil {
		t.Skip("zbarimg isn't installed (apt install zbar-tools)")
	}
	dir := t.TempDir()
	for n := 1; n <= 120; n += 3 {
		url := setupURL(n)
		d, err := QR([]byte(url))
		if err != nil {
			t.Fatal(err)
		}
		for _, scale := range []int{3, 6} {
			name := filepath.Join(dir, "code.png")
			writePNG(t, d.Image(scale), name)
			out, err := exec.Command(zbar, "--quiet", "--raw", "-Sdisable", "-Sqrcode.enable", name).Output()
			if got := strings.TrimSuffix(string(out), "\n"); err != nil || got != url {
				t.Errorf("%d-byte link at %d px a module: zbar read %q, %v", len(url), scale, got, err)
			}
		}
	}
}

// TestQR_DonutWhenThereIsRoom checks that links of the lengths people's
// host names give carry the donut, a third of the code across, and that
// longer ones still make a code.
func TestQR_DonutWhenThereIsRoom(t *testing.T) {
	for _, tt := range []struct {
		host  int
		donut bool
	}{
		{4, true}, {16, true}, {21, true}, {37, true}, {38, false}, {150, false},
	} {
		url := setupURL(tt.host)
		d, err := QR([]byte(url))
		if err != nil {
			t.Fatalf("%d-character host: %v", tt.host, err)
		}
		svg := d.SVG("setup link")
		if got := strings.Contains(svg, hexOf(Glaze)); got != tt.donut {
			t.Errorf("%d-byte link: donut %v, want %v", len(url), got, tt.donut)
		}
	}
	if _, err := QR([]byte(strings.Repeat("x", 300))); err == nil {
		t.Error("QR encoded more than a version 10 code holds")
	}
}

func hexOf(c interface{ RGBA() (r, g, b, a uint32) }) string {
	r, g, b, _ := c.RGBA()
	const digits = "0123456789abcdef"
	out := []byte{'#'}
	for _, v := range []uint32{r >> 8, g >> 8, b >> 8} {
		out = append(out, digits[v>>4], digits[v&15])
	}
	return string(out)
}

// TestQR_HoleKeepsHalfTheCorrection checks the bound the donut's hole is
// drawn within.
func TestQR_HoleKeepsHalfTheCorrection(t *testing.T) {
	for _, level := range []qr.Level{qr.Q, qr.H} {
		c, err := qr.EncodeVersion([]byte(setupURL(16)), level, 6)
		if err != nil {
			t.Fatal(err)
		}
		if r := c.Hole(0.5); 2*r < 0.25*float64(c.Size()) || 2*r > 0.4*float64(c.Size()) {
			t.Errorf("version 6-%v hole of radius %v, out of %d modules", level, r, c.Size())
		}
	}
}

// TestPreview writes the code to $DOH_QR_PREVIEW, to look at.
func TestPreview(t *testing.T) {
	out := os.Getenv("DOH_QR_PREVIEW")
	if out == "" {
		t.Skip("set DOH_QR_PREVIEW to a directory to write previews")
	}
	for name, url := range map[string]string{"short": setupURL(16), "long": setupURL(60)} {
		d, err := QR([]byte(url))
		if err != nil {
			t.Fatal(err)
		}
		writePNG(t, d.Image(12), filepath.Join(out, name+".png"))
		if err := os.WriteFile(filepath.Join(out, name+".svg"), []byte(d.SVG(url)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
