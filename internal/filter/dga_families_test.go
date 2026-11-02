package filter

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
)

// DGA families, reimplemented in the spirit of published analyses of
// malware's domain generation algorithms (such as those collected by
// DGArchive and in github.com/baderj/domain_generation_algorithms), to
// test the scorer against the kinds of names they make. They follow each
// family's construction (its alphabet, length range, and how characters
// are chosen), not its exact seeds or dates, and their output hasn't been
// compared with names captured from real infections.
var dgaFamilies = []struct {
	name string

	// minRecall is the share of the family's scored names the scorer must
	// flag at the default threshold, measured when it was chosen and
	// rounded down. Families that build names from words or pronounceable
	// syllables look like ordinary names to it, and short names are too
	// short to score, so some families have none.
	minRecall float64

	generate func(n int) []string
}{
	{"cryptolocker", 0.4, cryptolocker},
	{"ramnit", 0.4, ramnit},
	{"necurs", 0.4, necurs},
	{"conficker", 0, conficker},
	{"bamital (md5 hex)", 0.99, bamital},
	{"gameover (base 36)", 0.99, gameover},
	{"simda (pronounceable)", 0, simda},
	{"suppobox (dictionary)", 0, suppobox},
}

// cryptolocker generates CryptoLocker's shifting-register names: 12 to 16
// letters from three registers seeded by the date.
func cryptolocker(n int) []string {
	var out []string
	for i := range n {
		day, month, year := uint32(1+i%28), uint32(1+i%12), uint32(2013+i%5)+uint32(i)
		length := 12 + i%5
		var b strings.Builder
		for range length {
			day = ((day ^ (day << 13)) >> 19) ^ ((day & 0xFFFFFFFE) << 12)
			month = ((month ^ (4 * month)) >> 25) ^ (16 * (month & 0xFFFFFFF8))
			year = ((year ^ (8 * year)) >> 11) ^ ((year & 0xFFFFFFF0) << 17)
			b.WriteByte(byte('a' + (day^month^year)%25))
		}
		out = append(out, b.String())
	}
	return out
}

// ramnit generates Ramnit's names: 8 to 19 letters from a Park-Miller
// generator.
func ramnit(n int) []string {
	seed := uint32(0x4f2a1d9c)
	next := func(mod uint32) uint32 {
		ix := seed
		ix = 16807*(ix%127773) - 2836*(ix/127773)
		seed = ix
		return ix % mod
	}
	var out []string
	for range n {
		a := seed
		length := next(12) + 8
		b := seed
		var s strings.Builder
		for range length {
			s.WriteByte(byte('a' + next(25)))
		}
		out = append(out, s.String())
		m := uint64(a) * uint64(b)
		seed = uint32((m + m>>32) % (1 << 32))
	}
	return out
}

// necurs generates Necurs-like names: 7 to 21 letters from a 64-bit
// mixing function.
func necurs(n int) []string {
	var out []string
	x := uint64(0x9e3779b97f4a7c15)
	mix := func() uint64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return x
	}
	for range n {
		length := 7 + mix()%15
		var s strings.Builder
		for range length {
			s.WriteByte(byte('a' + mix()%26))
		}
		out = append(out, s.String())
	}
	return out
}

// conficker generates Conficker-like names: 4 to 10 letters, so many are
// too short to score.
func conficker(n int) []string {
	var out []string
	x := uint32(12345)
	rnd := func() uint32 {
		x = x*1103515245 + 12345
		return (x >> 16) & 0x7fff
	}
	for range n {
		length := 4 + rnd()%7
		var s strings.Builder
		for range length {
			s.WriteByte(byte('a' + rnd()%26))
		}
		out = append(out, s.String())
	}
	return out
}

// bamital generates Bamital's names: the hex MD5 of a seed and counter.
func bamital(n int) []string {
	var out []string
	for i := range n {
		sum := md5.Sum([]byte("bamital-seed-" + string(rune('a'+i%26)) + hex.EncodeToString([]byte{byte(i), byte(i >> 8)})))
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return out
}

// gameover generates names like newGOZ's: a hash in base 36, 20 to 28
// characters.
func gameover(n int) []string {
	var out []string
	for i := range n {
		var seed [8]byte
		binary.BigEndian.PutUint64(seed[:], uint64(i)*0x9e3779b9)
		sum := sha256.Sum256(seed[:])
		s := new(big.Int).SetBytes(sum[:]).Text(36)
		out = append(out, s[:20+i%9])
	}
	return out
}

// simda generates Simda-like names, alternating consonants and vowels,
// 7 to 11 characters, which read as pronounceable.
func simda(n int) []string {
	const consonants, vowels = "bcdfghjklmnpqrstvwxz", "aeiouy"
	var out []string
	x := uint32(7)
	rnd := func(m int) int {
		x = x*1664525 + 1013904223
		return int(x>>8) % m
	}
	for range n {
		length := 7 + rnd(5)
		var s strings.Builder
		for j := range length {
			if j%2 == 0 {
				s.WriteByte(consonants[rnd(len(consonants))])
			} else {
				s.WriteByte(vowels[rnd(len(vowels))])
			}
		}
		out = append(out, s.String())
	}
	return out
}

// suppobox generates Suppobox-like names: two English words run together.
func suppobox(n int) []string {
	words := strings.Fields(`able above action after again against almost always amount animal answer
		another around arrive basket battle beauty became before began behind believe better between
		bottom bread bright brother brought building butter careful carry center chance change charge
		children choose circle clothes cloud coast common complete corner cotton country course cover
		danger decide degree depend design desert develop dinner direct doctor dollar double dream
		during early earth either energy enough evening every example except expect experience family
		father favor feather field figure finger finish flower follow forest forward friend garden
		gather gentle glass govern ground group guess happen heaven heavy history honor horse hundred
		island itself journey kitchen language laugh leather letter listen little machine market master
		matter measure middle minute modern moment morning mother mountain music nation nature neighbor
		number object ocean office orange order other paper party people perhaps person picture planet
		pleasant pocket position power present pretty problem promise public purpose question quiet
		rather reason record region remember result river rubber safety science season second settle
		shake shoulder silver simple single sister soldier spring square station stream strong student
		subject summer supply system teacher temple thousand through together travel trouble village
		weather window winter wonder yellow`)
	var out []string
	x := uint32(99)
	rnd := func(m int) int {
		x = x*22695477 + 1
		return int(x>>10) % m
	}
	for range n {
		out = append(out, words[rnd(len(words))]+words[rnd(len(words))])
	}
	return out
}
