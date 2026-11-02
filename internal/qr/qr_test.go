package qr

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReedSolomon checks error correction against the worked example in
// ISO/IEC 18004 (Annex I): "01234567" at version 1-M.
func TestReedSolomon(t *testing.T) {
	data := []byte{0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11}
	want := []byte{0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55}
	if got := remainder(data, generator(10)); !bytes.Equal(got, want) {
		t.Errorf("error correction = % X, want % X", got, want)
	}
}

// TestFormatAndVersionBits checks the BCH-coded format and version
// information against the standard's tables (Annex C and D).
func TestFormatAndVersionBits(t *testing.T) {
	for _, tt := range []struct {
		level Level
		mask  int
		want  int
	}{
		{M, 0, 0b101010000010010},
		{L, 4, 0b110011000101111},
		{H, 7, 0b000100000111011},
		{Q, 2, 0b011111100110001},
	} {
		if got := formatBits(tt.level, tt.mask); got != tt.want {
			t.Errorf("format %v/%d = %015b, want %015b", tt.level, tt.mask, got, tt.want)
		}
	}
	c := &Code{Version: 7, size: 45, modules: make([]bool, 45*45), function: make([]bool, 45*45), codeword: make([]int16, 45*45)}
	c.drawVersion()
	// Version 7's information is 000111 110010010100, read from the
	// bottom right of the block beside the bottom left finder.
	got := 0
	for i := 17; i >= 0; i-- {
		got <<= 1
		if c.Dark(i/3, c.size-11+i%3) {
			got |= 1
		}
	}
	if want := 0b000111110010010100; got != want {
		t.Errorf("version 7 information = %018b, want %018b", got, want)
	}
}

func TestCapacity(t *testing.T) {
	for _, tt := range []struct {
		version int
		level   Level
		want    int
	}{
		{1, L, 17}, {1, M, 14}, {1, Q, 11}, {1, H, 7},
		{5, M, 84}, {7, Q, 86}, {10, L, 271}, {10, M, 213}, {10, H, 119},
	} {
		if got := capacity(tt.version, tt.level); got != tt.want {
			t.Errorf("capacity(%d-%v) = %d, want %d", tt.version, tt.level, got, tt.want)
		}
	}
	for v := 1; v <= MaxVersion; v++ {
		for l := L; l <= H; l++ {
			b := table[v][l]
			total := b.dataCodewords() + (b.count1+b.count2)*b.ec
			want := [MaxVersion + 1]int{0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346}[v]
			if total != want {
				t.Errorf("version %d-%v has %d codewords, want %d", v, l, total, want)
			}
		}
	}
}

func TestEncode_Errors(t *testing.T) {
	if _, err := Encode(make([]byte, 214), M); !errors.Is(err, ErrTooLong) {
		t.Errorf("214 bytes at M: %v", err)
	}
	if _, err := Encode([]byte("x"), Level(9)); err == nil {
		t.Error("an unknown level was accepted")
	}
	for name, f := range map[string]func() error{
		"version 0":  func() error { _, err := EncodeMask([]byte("x"), M, 0, 0); return err },
		"version 11": func() error { _, err := EncodeMask([]byte("x"), M, 11, 0); return err },
		"mask 8":     func() error { _, err := EncodeMask([]byte("x"), M, 1, 8); return err },
		"too long":   func() error { _, err := EncodeMask(make([]byte, 15), M, 1, 0); return err },
	} {
		if f() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestEncode_ChoosesTheSmallestVersion(t *testing.T) {
	for n, want := range map[int]int{1: 1, 14: 1, 15: 2, 84: 5, 85: 6, 213: 10} {
		c, err := Encode(bytes.Repeat([]byte("a"), n), M)
		if err != nil || c.Version != want || c.Size() != 17+4*want {
			t.Errorf("%d bytes at M: version %v, %v; want %d", n, c.Version, err, want)
		}
	}
}

// png renders c with a quiet zone, scale pixels per module.
func writePNG(t *testing.T, c *Code, scale int, name string) {
	t.Helper()
	const quiet = 4
	side := (c.Size() + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for y := range side {
		for x := range side {
			v := color.Gray{255}
			if c.Dark(x/scale-quiet, y/scale-quiet) {
				v = color.Gray{0}
			}
			img.SetGray(x, y, v)
		}
	}
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

// TestDecodesWithZBar checks codes against an independent decoder, ZBar,
// for every version, level, and mask, if zbarimg is installed: the codes
// people's phones will read.
func TestDecodesWithZBar(t *testing.T) {
	zbar, err := exec.LookPath("zbarimg")
	if err != nil {
		t.Skip("zbarimg isn't installed (apt install zbar-tools)")
	}
	rng := rand.New(rand.NewPCG(1, 2))
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?#[]@!$&'()*+,;="
	dir := t.TempDir()
	var cases []string
	for v := 1; v <= MaxVersion; v++ {
		for l := L; l <= H; l++ {
			for mask := range 8 {
				// Fill the version, so every codeword matters.
				n := capacity(v, l)
				if mask%2 == 1 {
					n = 1 + rng.IntN(n) // and sometimes not
				}
				data := make([]byte, n)
				for i := range data {
					data[i] = alphabet[rng.IntN(len(alphabet))]
				}
				c, err := EncodeMask(data, l, v, mask)
				if err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(dir, fmt.Sprintf("v%d-%v-m%d.png", v, l, mask))
				writePNG(t, c, 4, name)
				cases = append(cases, name+"\x00"+string(data))
			}
		}
	}
	for _, tc := range cases {
		name, want, _ := strings.Cut(tc, "\x00")
		out, err := exec.Command(zbar, "--quiet", "--raw", "-Sdisable", "-Sqrcode.enable", name).Output()
		if got := strings.TrimSuffix(string(out), "\n"); err != nil || got != want {
			t.Errorf("%s: zbar read %q, %v; want %q", filepath.Base(name), got, err, want)
		}
	}

	// And codes Encode chooses for, such as setup links.
	for _, s := range []string{"https://dns.example.com/setup/RfcDwNWF3WMikylWanaHcg", "x"} {
		c, err := Encode([]byte(s), M)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(dir, "auto.png")
		writePNG(t, c, 3, name)
		out, err := exec.Command(zbar, "--quiet", "--raw", name).Output()
		if got := strings.TrimSuffix(string(out), "\n"); err != nil || got != s {
			t.Errorf("%q (version %d, mask %d): zbar read %q, %v", s, c.Version, c.Mask, got, err)
		}
	}
}

func TestRenderings(t *testing.T) {
	c, err := Encode([]byte("https://example.com"), M)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := c.WriteText(&b, 2); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if want := (c.Size() + 4 + 1) / 2; len(lines) != want {
		t.Errorf("%d text lines, want %d", len(lines), want)
	}
}

// TestFunctionPatterns checks the fixed patterns readers rely on that
// decoding alone doesn't: the dark module, the timing patterns, and the
// finders' centers and separators.
func TestFunctionPatterns(t *testing.T) {
	for v := 1; v <= MaxVersion; v++ {
		c, err := EncodeMask([]byte("doh"), M, v, v%8)
		if err != nil {
			t.Fatal(err)
		}
		n := c.Size()
		if !c.Dark(8, 4*v+9) {
			t.Errorf("version %d: no dark module at (8, %d)", v, 4*v+9)
		}
		for i := 8; i < n-8; i++ {
			if c.Dark(i, 6) != (i%2 == 0) || c.Dark(6, i) != (i%2 == 0) {
				t.Errorf("version %d: timing pattern broken at %d", v, i)
				break
			}
		}
		for _, at := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} {
			if !c.Dark(at[0], at[1]) || c.Dark(at[0]+2, at[1]) || !c.Dark(at[0]+3, at[1]) {
				t.Errorf("version %d: finder at %v is wrong", v, at)
			}
		}
		if c.Dark(7, 7) || c.Dark(n-8, 7) || c.Dark(7, n-8) {
			t.Errorf("version %d: a finder's separator is dark", v)
		}
	}
}
