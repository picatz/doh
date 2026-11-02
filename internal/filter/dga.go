package filter

import (
	"fmt"
	"math"
	"strings"
)

//go:generate go run dga_model_gen.go

// dgaSymbols is the number of symbols in the DGA model: a to z, 0 to 9,
// the hyphen, and the boundary before and after a label.
const dgaSymbols = 38

const dgaBoundary = dgaSymbols - 1

// DGA thresholds.
const (
	// dgaMinLength is the shortest label scored: shorter ones are too few
	// characters to tell apart from abbreviations and brand names.
	dgaMinLength = 8

	// DefaultDGAThreshold is the score above which a label is flagged. It
	// was chosen with TestDGA_Curve to flag about 0.1% of popular domains'
	// labels the model wasn't trained on, giving up recall for that:
	// about half of the names from generators that pick random letters
	// score above it, and nearly all hex and base-36 names.
	DefaultDGAThreshold = 20.0
)

// dgaSymbol returns c's symbol in the model, or -1.
func dgaSymbol(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= '0' && c <= '9':
		return 26 + int(c-'0')
	case c == '-':
		return 36
	}
	return -1
}

// DGAFeatures are what [DGAScore] measures in a label.
type DGAFeatures struct {
	// Length is the label's length in bytes.
	Length int

	// Surprise is the label's average surprise under the bigram model of
	// popular domains' labels, in bits per character: how unlikely each
	// character is after the one before it. Popular domains' labels have
	// a median of 4; random letters about 5.6, and hex about 6.6.
	Surprise float64

	// Entropy is the Shannon entropy of the label's characters, in bits.
	Entropy float64

	// ConsonantRun is the longest run of consonants, counting y as a
	// vowel and digits as consonants.
	ConsonantRun int

	// Digits is the fraction of characters that are digits.
	Digits float64

	// Switches is how many times the label changes between digits and
	// letters next to each other: hex and base-36 strings switch often,
	// while names with numbers in them, such as bet365, switch once or
	// twice.
	Switches int
}

// DGAScore scores label, a registrable domain's own label such as
// "example" in example.com, for how machine-generated it looks: positive
// scores look generated, and the higher, the more so. It returns false
// for labels it doesn't score: shorter than 8 characters,
// internationalized (Punycode), or with characters other than lower-case
// letters, digits, and hyphens.
//
// The score is the label's total surprise under a bigram model of
// popular domains' labels, beyond a baseline of 4.4 bits per character,
// so longer labels give more evidence either way, plus penalties for
// switching between digits and letters more than twice and for runs of
// more than five consonants. It's meant to be compared with
// [DefaultDGAThreshold]. Names from generators that pick random letters,
// hex, or base-36 strings score high; ones built from dictionary words or
// from alternating consonants and vowels, as some malware families do,
// score like ordinary names and aren't caught. Entropy and the share of
// digits are reported but not scored: in testing they didn't separate
// generated names from popular ones better than surprise does.
func DGAScore(label string) (float64, DGAFeatures, bool) {
	f := DGAFeatures{Length: len(label)}
	if len(label) < dgaMinLength || len(label) > maxLabel || strings.HasPrefix(label, "xn--") {
		return 0, f, false
	}

	var counts [dgaSymbols]uint8
	var surprise float64
	prev, run, digits := dgaBoundary, 0, 0
	for i := range len(label) {
		c := label[i]
		s := dgaSymbol(c)
		if s < 0 {
			return 0, f, false
		}
		counts[s]++
		surprise -= float64(dgaBigram[prev*dgaSymbols+s])
		if digit, prevDigit := s >= 26 && s < 36, prev >= 26 && prev < 36; s != 36 && prev < 36 && digit != prevDigit {
			f.Switches++
		}
		prev = s

		switch {
		case c >= '0' && c <= '9':
			digits++
			run++
		case c == 'a', c == 'e', c == 'i', c == 'o', c == 'u', c == 'y', c == '-':
			run = 0
		default:
			run++
		}
		f.ConsonantRun = max(f.ConsonantRun, run)
	}
	surprise -= float64(dgaBigram[prev*dgaSymbols+dgaBoundary])

	n := float64(len(label))
	f.Surprise = surprise / (n + 1)
	f.Digits = float64(digits) / n
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			f.Entropy -= p * math.Log2(p)
		}
	}

	score := (f.Surprise - dgaSurpriseBaseline) * (n + 1)
	score += dgaSwitchWeight * float64(max(f.Switches-2, 0))
	score += dgaRunWeight * float64(max(f.ConsonantRun-5, 0))
	return score, f, true
}

// The score's terms: dgaSurpriseBaseline is subtracted from a label's
// average surprise, so typical names score below zero, and the weights
// add to it for each switch between digits and letters past two, and
// each consonant in a row past five.
const (
	dgaSurpriseBaseline = 4.4
	dgaSwitchWeight     = 2
	dgaRunWeight        = 1
)

// dga reports whether registrable's label scores above threshold, with
// a reason for explanations.
func dga(registrable string, threshold float64) (string, bool) {
	label, _, _ := strings.Cut(registrable, ".")
	score, f, ok := DGAScore(label)
	if !ok || score <= threshold {
		return "", false
	}
	return fmt.Sprintf("%s looks machine-generated (score %.1f over %.1f: %.1f bits of surprise per character, %d consonants in a row, %.0f%% digits)",
		registrable, score, threshold, f.Surprise, f.ConsonantRun, 100*f.Digits), true
}
