// Package qr encodes QR codes ([ISO/IEC 18004]), so a device can be set
// up by pointing its camera at a screen.
//
// It encodes bytes in byte mode, at versions 1 to 10 (up to 271 bytes at
// error correction level L, 213 at M), with any of the four error
// correction levels, choosing the mask the standard's penalty rules
// prefer. That covers URLs, which is what doh needs; it doesn't do
// numeric, alphanumeric, or kanji modes, or larger versions.
//
// A [Code] renders as SVG path data, for pages to draw, or as text for a
// terminal.
//
// [ISO/IEC 18004]: https://www.iso.org/standard/83389.html
package qr

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Level is an error correction level: how much of a code can be damaged
// and still read.
type Level int

// Error correction levels, from least to most robust.
const (
	L Level = iota // about 7%
	M              // about 15%
	Q              // about 25%
	H              // about 30%
)

func (l Level) String() string {
	if l < L || l > H {
		return fmt.Sprintf("Level(%d)", int(l))
	}
	return "LMQH"[l : l+1]
}

// MaxVersion is the largest version encoded.
const MaxVersion = 10

// ErrTooLong reports data that doesn't fit in a version 1 to 10 code at
// the level asked for.
var ErrTooLong = errors.New("qr: data too long")

// Code is an encoded QR code: a square of dark and light modules.
type Code struct {
	// Version is the code's version, 1 to 10; it has 17 + 4×Version
	// modules on a side.
	Version int

	// Level is its error correction level.
	Level Level

	// Mask is the mask pattern applied, 0 to 7.
	Mask int

	size     int
	modules  []bool // dark modules, row by row
	function []bool // finder, timing, alignment, format, and version modules
}

// Size returns how many modules the code has on a side, without a quiet
// zone.
func (c *Code) Size() int { return c.size }

// Dark reports whether the module at column x, row y is dark. Modules
// outside the code, such as in its quiet zone, are light.
func (c *Code) Dark(x, y int) bool {
	if x < 0 || y < 0 || x >= c.size || y >= c.size {
		return false
	}
	return c.modules[y*c.size+x]
}

// Encode encodes data as the smallest QR code that holds it at level,
// choosing the mask with the lowest penalty.
func Encode(data []byte, level Level) (*Code, error) {
	if level < L || level > H {
		return nil, fmt.Errorf("qr: invalid level %d", level)
	}
	for v := 1; v <= MaxVersion; v++ {
		if len(data) <= capacity(v, level) {
			return encode(data, v, level, -1), nil
		}
	}
	return nil, fmt.Errorf("%w: %d bytes, at most %d at level %v", ErrTooLong, len(data), capacity(MaxVersion, level), level)
}

// EncodeMask encodes data at exactly version and mask, for tests and for
// anyone who must; Encode chooses well on its own.
func EncodeMask(data []byte, level Level, version, mask int) (*Code, error) {
	switch {
	case level < L || level > H:
		return nil, fmt.Errorf("qr: invalid level %d", level)
	case version < 1 || version > MaxVersion:
		return nil, fmt.Errorf("qr: version %d isn't 1 to %d", version, MaxVersion)
	case mask < 0 || mask > 7:
		return nil, fmt.Errorf("qr: mask %d isn't 0 to 7", mask)
	case len(data) > capacity(version, level):
		return nil, fmt.Errorf("%w: %d bytes, at most %d at version %d-%v", ErrTooLong, len(data), capacity(version, level), version, level)
	}
	return encode(data, version, level, mask), nil
}

// blocks describes a version and level's error correction: the codewords
// of error correction per block, and the blocks' data codewords, in one
// or two groups.
type blocks struct {
	ec            int
	count1, data1 int
	count2, data2 int
}

func (b blocks) dataCodewords() int { return b.count1*b.data1 + b.count2*b.data2 }

// table is the error correction structure of versions 1 to 10, by level
// (ISO/IEC 18004, Table 9).
var table = [MaxVersion + 1][4]blocks{
	1:  {{7, 1, 19, 0, 0}, {10, 1, 16, 0, 0}, {13, 1, 13, 0, 0}, {17, 1, 9, 0, 0}},
	2:  {{10, 1, 34, 0, 0}, {16, 1, 28, 0, 0}, {22, 1, 22, 0, 0}, {28, 1, 16, 0, 0}},
	3:  {{15, 1, 55, 0, 0}, {26, 1, 44, 0, 0}, {18, 2, 17, 0, 0}, {22, 2, 13, 0, 0}},
	4:  {{20, 1, 80, 0, 0}, {18, 2, 32, 0, 0}, {26, 2, 24, 0, 0}, {16, 4, 9, 0, 0}},
	5:  {{26, 1, 108, 0, 0}, {24, 2, 43, 0, 0}, {18, 2, 15, 2, 16}, {22, 2, 11, 2, 12}},
	6:  {{18, 2, 68, 0, 0}, {16, 4, 27, 0, 0}, {24, 4, 19, 0, 0}, {28, 4, 15, 0, 0}},
	7:  {{20, 2, 78, 0, 0}, {18, 4, 31, 0, 0}, {18, 2, 14, 4, 15}, {26, 4, 13, 1, 14}},
	8:  {{24, 2, 97, 0, 0}, {22, 2, 38, 2, 39}, {22, 4, 18, 2, 19}, {26, 4, 14, 2, 15}},
	9:  {{30, 2, 116, 0, 0}, {22, 3, 36, 2, 37}, {20, 4, 16, 4, 17}, {24, 4, 12, 4, 13}},
	10: {{18, 2, 68, 2, 69}, {26, 4, 43, 1, 44}, {24, 6, 19, 2, 20}, {28, 6, 15, 2, 16}},
}

// alignment is where alignment patterns' centers go, on both axes, by
// version (ISO/IEC 18004, Annex E).
var alignment = [MaxVersion + 1][]int{
	2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50},
}

// countBits is how many bits byte mode's character count takes.
func countBits(version int) int {
	if version <= 9 {
		return 8
	}
	return 16
}

// capacity returns how many bytes a version and level hold in byte mode.
func capacity(version int, level Level) int {
	bits := table[version][level].dataCodewords()*8 - 4 - countBits(version)
	return bits / 8
}

// encode builds the code. A mask of -1 chooses the best.
func encode(data []byte, version int, level Level, mask int) *Code {
	codewords := interleave(dataCodewords(data, version, level), table[version][level])

	c := &Code{Version: version, Level: level, size: 17 + 4*version}
	c.modules = make([]bool, c.size*c.size)
	c.function = make([]bool, c.size*c.size)
	c.drawFunctionPatterns()
	c.drawCodewords(codewords)

	if mask < 0 {
		best := -1
		for m := range 8 {
			c.applyMask(m)
			c.drawFormat(m)
			if p := c.penalty(); best < 0 || p < best {
				best, mask = p, m
			}
			c.applyMask(m) // masking twice undoes it
		}
	}
	c.Mask = mask
	c.applyMask(mask)
	c.drawFormat(mask)
	return c
}

// dataCodewords returns data in byte mode, terminated and padded to fill
// the version's data codewords (ISO/IEC 18004, 7.4).
func dataCodewords(data []byte, version int, level Level) []byte {
	var b bitBuffer
	b.append(0b0100, 4) // byte mode
	b.append(uint32(len(data)), countBits(version))
	for _, d := range data {
		b.append(uint32(d), 8)
	}
	capBits := table[version][level].dataCodewords() * 8
	b.append(0, min(4, capBits-b.n))                           // terminator
	b.append(0, (8-b.n%8)%8)                                   // to a byte boundary
	for pad := byte(0xEC); b.n < capBits; pad ^= 0xEC ^ 0x11 { // alternate pad bytes
		b.append(uint32(pad), 8)
	}
	return b.bytes
}

// interleave splits data into blocks, adds each block's error correction
// codewords, and interleaves them (ISO/IEC 18004, 7.5 and 7.6).
func interleave(data []byte, bl blocks) []byte {
	var split [][]byte
	for range bl.count1 {
		split, data = append(split, data[:bl.data1]), data[bl.data1:]
	}
	for range bl.count2 {
		split, data = append(split, data[:bl.data2]), data[bl.data2:]
	}

	gen := generator(bl.ec)
	var out []byte
	longest := max(bl.data1, bl.data2)
	for i := range longest {
		for _, blk := range split {
			if i < len(blk) {
				out = append(out, blk[i])
			}
		}
	}
	ecs := make([][]byte, len(split))
	for i, blk := range split {
		ecs[i] = remainder(blk, gen)
	}
	for i := range bl.ec {
		for _, ec := range ecs {
			out = append(out, ec[i])
		}
	}
	return out
}

// bitBuffer collects bits, most significant first.
type bitBuffer struct {
	bytes []byte
	n     int
}

func (b *bitBuffer) append(v uint32, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if b.n%8 == 0 {
			b.bytes = append(b.bytes, 0)
		}
		if v>>uint(i)&1 == 1 {
			b.bytes[b.n/8] |= 0x80 >> uint(b.n%8)
		}
		b.n++
	}
}

// Reed–Solomon arithmetic over GF(256) with the QR code's primitive
// polynomial, x⁸ + x⁴ + x³ + x² + 1 (0x11D).

var exp, log = func() (exp [512]byte, log [256]byte) {
	x := 1
	for i := range 255 {
		exp[i], log[x] = byte(x), byte(i)
		if x <<= 1; x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		exp[i] = exp[i-255]
	}
	return
}()

func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return exp[int(log[a])+int(log[b])]
}

// generator returns the generator polynomial of degree n, (x − α⁰)(x − α¹)
// …(x − αⁿ⁻¹), highest power first, without its leading 1.
func generator(n int) []byte {
	g := []byte{1}
	for i := range n {
		next := make([]byte, len(g)+1)
		for j, c := range g {
			next[j] ^= c
			next[j+1] ^= mul(c, exp[i])
		}
		g = next
	}
	return g[1:]
}

// remainder returns the error correction codewords of data: the remainder
// of data × xⁿ divided by gen.
func remainder(data, gen []byte) []byte {
	r := make([]byte, len(gen))
	for _, d := range data {
		f := d ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i, g := range gen {
			r[i] ^= mul(g, f)
		}
	}
	return r
}

// set draws a function module.
func (c *Code) set(x, y int, dark bool) {
	c.modules[y*c.size+x] = dark
	c.function[y*c.size+x] = true
}

// drawFunctionPatterns draws the finder, separator, timing, and alignment
// patterns, reserves the format and version areas, and draws the version
// information and the dark module.
func (c *Code) drawFunctionPatterns() {
	n := c.size
	for i := range n {
		c.set(6, i, i%2 == 0)
		c.set(i, 6, i%2 == 0)
	}
	for _, at := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := at[0]+dx, at[1]+dy
				if x < 0 || y < 0 || x >= n || y >= n {
					continue
				}
				d := max(abs(dx), abs(dy))
				c.set(x, y, d != 2 && d != 4)
			}
		}
	}
	pos := alignment[c.Version]
	for i, ay := range pos {
		for j, ax := range pos {
			// Not over the finder patterns.
			if (i == 0 && j == 0) || (i == 0 && j == len(pos)-1) || (i == len(pos)-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					c.set(ax+dx, ay+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	c.drawFormat(0) // reserves the area; drawn again once the mask is known
	c.drawVersion()
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// formatBits returns the 15 format bits for level and mask: 5 data bits,
// 10 BCH error correction bits, XORed with 101010000010010 (ISO/IEC
// 18004, 7.9).
func formatBits(level Level, mask int) int {
	levelBits := [4]int{L: 1, M: 0, Q: 3, H: 2}[level]
	data := levelBits<<3 | mask
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	return (data<<10 | rem) ^ 0x5412
}

// drawFormat draws the format information, twice, and the dark module.
func (c *Code) drawFormat(mask int) {
	bits := formatBits(c.Level, mask)
	bit := func(i int) bool { return bits>>uint(i)&1 != 0 }
	n := c.size
	// Around the top left finder.
	for i := range 6 {
		c.set(8, i, bit(i))
	}
	c.set(8, 7, bit(6))
	c.set(8, 8, bit(7))
	c.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		c.set(14-i, 8, bit(i))
	}
	// Beside the top right and bottom left finders.
	for i := range 8 {
		c.set(n-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		c.set(8, n-15+i, bit(i))
	}
	c.set(8, n-8, true) // the dark module
}

// drawVersion draws the version information, for versions 7 and up: 6
// version bits and 12 BCH error correction bits (ISO/IEC 18004, 7.10).
func (c *Code) drawVersion() {
	if c.Version < 7 {
		return
	}
	rem := c.Version
	for range 12 {
		rem = rem<<1 ^ (rem>>11)*0x1F25
	}
	bits := c.Version<<12 | rem
	for i := range 18 {
		dark := bits>>uint(i)&1 != 0
		a, b := c.size-11+i%3, i/3
		c.set(a, b, dark)
		c.set(b, a, dark)
	}
}

// drawCodewords places codewords in the zigzag the standard reads them
// in: two columns at a time from the right, upward then downward, skipping
// the vertical timing pattern (ISO/IEC 18004, 7.7.3).
func (c *Code) drawCodewords(codewords []byte) {
	n, i := c.size, 0
	for right := n - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		upward := (right+1)&2 == 0
		for vert := range n {
			y := vert
			if upward {
				y = n - 1 - vert
			}
			for j := range 2 {
				x := right - j
				if c.function[y*n+x] {
					continue
				}
				// Past the codewords, remainder bits are light.
				if i < len(codewords)*8 {
					c.modules[y*n+x] = codewords[i/8]>>uint(7-i%8)&1 != 0
					i++
				}
			}
		}
	}
}

// masked reports whether mask m flips the module at column x, row y
// (ISO/IEC 18004, Table 10).
func masked(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

// applyMask flips the data modules mask m selects.
func (c *Code) applyMask(m int) {
	for y := range c.size {
		for x := range c.size {
			if i := y*c.size + x; !c.function[i] && masked(m, x, y) {
				c.modules[i] = !c.modules[i]
			}
		}
	}
}

// penalty scores the code by the standard's four rules; lower is easier
// to read (ISO/IEC 18004, 7.8.3).
func (c *Code) penalty() int {
	n, p := c.size, 0
	dark := func(x, y int) bool { return c.modules[y*n+x] }

	// Rule 1: runs of five or more of one color, in rows and columns.
	for _, rows := range []bool{true, false} {
		for a := range n {
			run, prev := 0, false
			for b := range n {
				x, y := b, a
				if !rows {
					x, y = a, b
				}
				if d := dark(x, y); b > 0 && d == prev {
					run++
				} else {
					if run >= 5 {
						p += 3 + run - 5
					}
					run, prev = 1, d
				}
			}
			if run >= 5 {
				p += 3 + run - 5
			}
		}
	}
	// Rule 2: two by two blocks of one color.
	for y := range n - 1 {
		for x := range n - 1 {
			d := dark(x, y)
			if d == dark(x+1, y) && d == dark(x, y+1) && d == dark(x+1, y+1) {
				p += 3
			}
		}
	}
	// Rule 3: finder-like patterns, 1:1:3:1:1 with four light modules on
	// one side.
	pattern := []bool{true, false, true, true, true, false, true}
	for _, rows := range []bool{true, false} {
		for a := range n {
			for b := 0; b+len(pattern) <= n; b++ {
				// at reports whether the module k after b is dark; outside
				// the code counts as light.
				at := func(k int) bool {
					pos := b + k
					if pos < 0 || pos >= n {
						return false
					}
					if rows {
						return dark(pos, a)
					}
					return dark(a, pos)
				}
				match := true
				for k, want := range pattern {
					if at(k) != want {
						match = false
						break
					}
				}
				if !match {
					continue
				}
				lightBefore, lightAfter := true, true
				for k := 1; k <= 4; k++ {
					if at(-k) {
						lightBefore = false
					}
					if at(len(pattern) - 1 + k) {
						lightAfter = false
					}
				}
				if lightBefore || lightAfter {
					p += 40
				}
			}
		}
	}
	// Rule 4: how far the share of dark modules is from half.
	darkCount := 0
	for _, d := range c.modules {
		if d {
			darkCount++
		}
	}
	percent := darkCount * 100 / (n * n)
	p += abs(percent-50) / 5 * 10
	return p
}

// SVGPath returns SVG path data that draws the code's dark modules, one
// unit per module, offset by a quiet zone of quiet modules on each side:
// draw it in a view box quiet×2 + Size units square.
func (c *Code) SVGPath(quiet int) string {
	var b strings.Builder
	for y := range c.size {
		for x := 0; x < c.size; {
			if !c.Dark(x, y) {
				x++
				continue
			}
			run := 1
			for c.Dark(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run
		}
	}
	return b.String()
}

// SVG returns the code as a standalone SVG image, dark on light.
func (c *Code) SVG(quiet int) string {
	side := c.size + 2*quiet
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path d="%s" fill="#000"/></svg>`,
		side, side, side, side, c.SVGPath(quiet))
}

// WriteText writes the code for a terminal: two rows per line with half
// block characters, dark on light whatever the terminal's colors, with
// ANSI colors, and a quiet zone of quiet modules.
func (c *Code) WriteText(w io.Writer, quiet int) error {
	const reset = "\x1b[0m"
	var b strings.Builder
	for y := -quiet; y < c.size+quiet; y += 2 {
		for x := -quiet; x < c.size+quiet; x++ {
			top, bottom := c.Dark(x, y), c.Dark(x, y+1)
			// Foreground is the top half, background the bottom.
			fg, bg := "97", "107"
			if top {
				fg = "30"
			}
			if bottom {
				bg = "40"
			}
			fmt.Fprintf(&b, "\x1b[%s;%sm▀", fg, bg)
		}
		b.WriteString(reset + "\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
