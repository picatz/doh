package qr

import "math"

// Hole returns the radius, in modules, of the largest circle centered on
// the code that can be cleared to light for a logo, such that every error
// correction block loses at most budget of the codewords it can correct,
// and no finder, timing, alignment, format, or version module is touched.
// It returns 0 if there's no room, as for versions 7 and up, whose center
// is an alignment pattern.
//
// A block of e error correction codewords corrects up to e/2 wrong
// codewords. Hole counts every codeword with a module in the circle as
// wrong, whatever its value, so with a budget of 0.5 a code with its hole
// cleared still corrects as many codewords per block as a level of half
// its strength, for smudges, glare, and focus.
func (c *Code) Hole(budget float64) float64 {
	budget = min(max(budget, 0), 1)
	allowed := int(budget * float64(c.ec/2))
	center := float64(c.size) / 2

	best := 0.0
	for r := 0.5; r < center; r += 0.25 {
		if !c.clearable(center, r, allowed) {
			break
		}
		best = r
	}
	return best
}

// clearable reports whether clearing the modules a circle overlaps
// leaves each block at most allowed wrong codewords, and no function
// module touched.
func (c *Code) clearable(center, r float64, allowed int) bool {
	wrong := map[int16]bool{}
	perBlock := map[int8]int{}
	for y := range c.size {
		for x := range c.size {
			if !c.Covers(x, y, r) {
				continue
			}
			i := y*c.size + x
			if c.function[i] {
				return false
			}
			cw := c.codeword[i]
			if cw < 0 || wrong[cw] {
				continue
			}
			wrong[cw] = true
			b := c.blockOf[cw]
			if perBlock[b]++; perBlock[b] > allowed {
				return false
			}
		}
	}
	return true
}

// Covers reports whether a circle of radius r, in modules, centered on
// the code overlaps the module at column x, row y.
func (c *Code) Covers(x, y int, r float64) bool {
	if r <= 0 {
		return false
	}
	center := float64(c.size) / 2
	// The distance from the center to the nearest point of the module.
	dx := max(float64(x)-center, 0, center-float64(x+1))
	dy := max(float64(y)-center, 0, center-float64(y+1))
	return math.Hypot(dx, dy) < r
}
