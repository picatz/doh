package safebrowsing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The Safe Browsing API answers in protocol buffers. This file decodes
// the few messages doh uses, by hand, from the field numbers in
// google/security/safebrowsing/v5/safebrowsing.proto, so doh needs no
// protobuf dependency. Unknown fields are skipped, as protobuf requires.

// Protobuf wire types.
const (
	wireVarint = 0
	wireI64    = 1
	wireBytes  = 2
	wireI32    = 5
)

var errTruncated = errors.New("safebrowsing: truncated message")

// field is one decoded field of a message.
type field struct {
	num   int
	wire  int
	value uint64 // varint, fixed64, or fixed32 value
	bytes []byte // length-delimited value
}

// fields calls f for each field in msg, stopping at the first error.
func fields(msg []byte, f func(field) error) error {
	for len(msg) > 0 {
		key, n := binary.Uvarint(msg)
		if n <= 0 {
			return errTruncated
		}
		msg = msg[n:]
		fl := field{num: int(key >> 3), wire: int(key & 7)}
		if fl.num == 0 || key>>3 > 1<<29 {
			return fmt.Errorf("safebrowsing: invalid field number %d", key>>3)
		}
		switch fl.wire {
		case wireVarint:
			v, n := binary.Uvarint(msg)
			if n <= 0 {
				return errTruncated
			}
			fl.value, msg = v, msg[n:]
		case wireI64:
			if len(msg) < 8 {
				return errTruncated
			}
			fl.value, msg = binary.LittleEndian.Uint64(msg), msg[8:]
		case wireI32:
			if len(msg) < 4 {
				return errTruncated
			}
			fl.value, msg = uint64(binary.LittleEndian.Uint32(msg)), msg[4:]
		case wireBytes:
			l, n := binary.Uvarint(msg)
			if n <= 0 || l > uint64(len(msg)-n) {
				return errTruncated
			}
			fl.bytes, msg = msg[n:n+int(l)], msg[n+int(l):]
		default:
			return fmt.Errorf("safebrowsing: unsupported wire type %d", fl.wire)
		}
		if err := f(fl); err != nil {
			return err
		}
	}
	return nil
}

// riceDeltas is a RiceDeltaEncoded32Bit message: sorted 32-bit values,
// the first as is and the rest as Golomb-Rice coded differences.
type riceDeltas struct {
	first   uint32
	k       int // the Rice parameter
	entries int // how many differences are encoded
	data    []byte
}

func parseRice(msg []byte) (riceDeltas, error) {
	var r riceDeltas
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireVarint:
			r.first = uint32(f.value)
		case f.num == 2 && f.wire == wireVarint:
			r.k = int(int32(f.value))
		case f.num == 3 && f.wire == wireVarint:
			r.entries = int(int32(f.value))
		case f.num == 4 && f.wire == wireBytes:
			r.data = f.bytes
		}
		return nil
	})
	return r, err
}

// maxEntries bounds how many values a list or update may hold, so a
// malformed or hostile response can't exhaust memory. Google's threat
// lists hold a few million 4-byte prefixes at most.
const maxEntries = 1 << 24

// decode returns the encoded values, which are sorted, since each is the
// one before plus a difference.
func (r riceDeltas) decode() ([]uint32, error) {
	if r.entries < 0 || r.entries >= maxEntries {
		return nil, fmt.Errorf("safebrowsing: %d entries", r.entries)
	}
	if r.entries == 0 && len(r.data) == 0 {
		return []uint32{r.first}, nil
	}
	if r.k < 1 || r.k > 32 {
		return nil, fmt.Errorf("safebrowsing: Rice parameter %d out of range", r.k)
	}
	// Each entry takes at least k+1 bits.
	if uint64(r.entries)*uint64(r.k+1) > uint64(len(r.data))*8 {
		return nil, errTruncated
	}

	values := make([]uint32, 0, r.entries+1)
	values = append(values, r.first)
	br := bitReader{data: r.data}
	v := uint64(r.first)
	for range r.entries {
		q := 0
		for {
			b, ok := br.bit()
			if !ok {
				return nil, errTruncated
			}
			if b == 0 {
				break
			}
			q++
			if uint64(q)<<r.k > 1<<32 {
				return nil, errors.New("safebrowsing: Rice-coded value overflows 32 bits")
			}
		}
		rem, ok := br.bits(r.k)
		if !ok {
			return nil, errTruncated
		}
		v += uint64(q)<<r.k | rem
		if v > 1<<32-1 {
			return nil, errors.New("safebrowsing: Rice-coded value overflows 32 bits")
		}
		values = append(values, uint32(v))
	}
	return values, nil
}

// bitReader reads bits from the least significant end of each byte, in
// order, as the Rice coder writes them.
type bitReader struct {
	data []byte
	pos  int // in bits
}

func (r *bitReader) bit() (uint64, bool) {
	if r.pos >= len(r.data)*8 {
		return 0, false
	}
	b := uint64(r.data[r.pos/8]>>(r.pos%8)) & 1
	r.pos++
	return b, true
}

// bits reads n bits, the first read being the least significant.
func (r *bitReader) bits(n int) (uint64, bool) {
	var v uint64
	for i := range n {
		b, ok := r.bit()
		if !ok {
			return 0, false
		}
		v |= b << i
	}
	return v, true
}

// HashList is an update to one of the server's hash lists, decoded from
// a HashList message.
type HashList struct {
	// Name is the list's name, such as "se-4b".
	Name string

	// Version is the list's version after the update, to send with the
	// next one. It's opaque.
	Version []byte

	// Partial is whether the update is relative to the version the
	// client sent, or else the whole list.
	Partial bool

	// Additions are 4-byte hash prefixes to add, as big-endian integers,
	// sorted.
	Additions []uint32

	// Removals are indices of prefixes to remove from the list, before
	// the additions are applied, sorted.
	Removals []uint32

	// MinWait is how long to wait before asking for the list again. Zero
	// means the server has more to send right away.
	MinWait time.Duration

	// Checksum is the SHA-256 of the list's sorted prefixes after the
	// update, or nil if the list didn't change.
	Checksum []byte
}

// parseHashList decodes a HashList message.
func parseHashList(msg []byte) (HashList, error) {
	var (
		h        HashList
		adds     *riceDeltas
		removals *riceDeltas
	)
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireBytes:
			h.Name = string(f.bytes)
		case f.num == 2 && f.wire == wireBytes:
			h.Version = f.bytes
		case f.num == 3 && f.wire == wireVarint:
			h.Partial = f.value != 0
		case f.num == 4 && f.wire == wireBytes:
			r, err := parseRice(f.bytes)
			if err != nil {
				return err
			}
			adds = &r
		case (f.num == 9 || f.num == 10 || f.num == 11) && f.wire == wireBytes:
			return fmt.Errorf("safebrowsing: hash list has prefixes longer than 4 bytes, which aren't supported")
		case f.num == 5 && f.wire == wireBytes:
			r, err := parseRice(f.bytes)
			if err != nil {
				return err
			}
			removals = &r
		case f.num == 6 && f.wire == wireBytes:
			d, err := parseDuration(f.bytes)
			if err != nil {
				return err
			}
			h.MinWait = d
		case f.num == 7 && f.wire == wireBytes:
			h.Checksum = f.bytes
		}
		return nil
	})
	if err != nil {
		return HashList{}, err
	}
	if adds != nil {
		if h.Additions, err = adds.decode(); err != nil {
			return HashList{}, err
		}
	}
	if removals != nil {
		if h.Removals, err = removals.decode(); err != nil {
			return HashList{}, err
		}
	}
	h.Version = append([]byte(nil), h.Version...)
	h.Checksum = append([]byte(nil), h.Checksum...)
	if len(h.Checksum) == 0 {
		h.Checksum = nil
	}
	return h, nil
}

// parseBatch decodes a BatchGetHashListsResponse.
func parseBatch(msg []byte) ([]HashList, error) {
	var lists []HashList
	err := fields(msg, func(f field) error {
		if f.num == 1 && f.wire == wireBytes {
			h, err := parseHashList(f.bytes)
			if err != nil {
				return err
			}
			lists = append(lists, h)
		}
		return nil
	})
	return lists, err
}

// ThreatType is a kind of threat, as the API numbers them.
type ThreatType int

// Threat types.
const (
	Malware                       ThreatType = 1
	SocialEngineering             ThreatType = 2
	UnwantedSoftware              ThreatType = 3
	PotentiallyHarmfulApplication ThreatType = 4
)

// String describes t for people.
func (t ThreatType) String() string {
	switch t {
	case Malware:
		return "malware"
	case SocialEngineering:
		return "phishing or social engineering"
	case UnwantedSoftware:
		return "unwanted software"
	case PotentiallyHarmfulApplication:
		return "potentially harmful application"
	}
	return fmt.Sprintf("threat type %d", int(t))
}

// FullHash is a full SHA-256 hash the server matched, with the threats it
// is listed for.
type FullHash struct {
	Hash    [32]byte
	Threats []ThreatType
}

// searchResult is a decoded SearchHashesResponse.
type searchResult struct {
	hashes []FullHash
	cache  time.Duration
}

// parseSearch decodes a SearchHashesResponse. Details with threat types
// or attributes it doesn't know are dropped, as the API asks, and so are
// those marked canary or frame-only, which don't apply to whole sites.
func parseSearch(msg []byte) (searchResult, error) {
	var r searchResult
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireBytes:
			h, err := parseFullHash(f.bytes)
			if err != nil {
				return err
			}
			if len(h.Threats) > 0 {
				r.hashes = append(r.hashes, h)
			}
		case f.num == 2 && f.wire == wireBytes:
			d, err := parseDuration(f.bytes)
			if err != nil {
				return err
			}
			r.cache = d
		}
		return nil
	})
	return r, err
}

func parseFullHash(msg []byte) (FullHash, error) {
	var h FullHash
	var hashLen int
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireBytes:
			if len(f.bytes) != 32 {
				return fmt.Errorf("safebrowsing: full hash of %d bytes", len(f.bytes))
			}
			hashLen = copy(h.Hash[:], f.bytes)
		case f.num == 2 && f.wire == wireBytes:
			t, ok, err := parseDetail(f.bytes)
			if err != nil {
				return err
			}
			if ok {
				h.Threats = append(h.Threats, t)
			}
		}
		return nil
	})
	if err == nil && hashLen == 0 {
		err = errors.New("safebrowsing: full hash missing")
	}
	return h, err
}

// parseDetail decodes a FullHashDetail, reporting whether it applies.
func parseDetail(msg []byte) (ThreatType, bool, error) {
	var t ThreatType
	applies := true
	// Canary and frame-only matches don't apply to a whole site, and
	// details with attributes it doesn't know a client must drop, so any
	// attribute drops the detail.
	attr := func(uint64) { applies = false }
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireVarint:
			t = ThreatType(f.value)
		case f.num == 2 && f.wire == wireVarint:
			attr(f.value)
		case f.num == 2 && f.wire == wireBytes: // packed
			for b := f.bytes; len(b) > 0; {
				v, n := binary.Uvarint(b)
				if n <= 0 {
					return errTruncated
				}
				attr(v)
				b = b[n:]
			}
		}
		return nil
	})
	if t < Malware || t > PotentiallyHarmfulApplication {
		applies = false
	}
	return t, applies, err
}

// parseDuration decodes a google.protobuf.Duration.
func parseDuration(msg []byte) (time.Duration, error) {
	var secs, nanos int64
	err := fields(msg, func(f field) error {
		switch {
		case f.num == 1 && f.wire == wireVarint:
			secs = int64(f.value)
		case f.num == 2 && f.wire == wireVarint:
			nanos = int64(int32(f.value))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if secs < 0 || nanos < 0 || secs > 365*24*3600 {
		return 0, fmt.Errorf("safebrowsing: duration of %ds out of range", secs)
	}
	return time.Duration(secs)*time.Second + time.Duration(nanos), nil
}

// prefixOf returns the 4-byte prefix of a full hash, as a big-endian
// integer.
func prefixOf(h [32]byte) uint32 { return binary.BigEndian.Uint32(h[:4]) }
