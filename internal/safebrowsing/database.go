package safebrowsing

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// prefixList is the local copy of one hash list: sorted, distinct 4-byte
// hash prefixes, and the version they're at.
type prefixList struct {
	version  []byte
	prefixes []uint32
}

// errChecksum reports a list that doesn't match the server's checksum
// after an update, which must then be fetched whole.
var errChecksum = errors.New("safebrowsing: list checksum mismatch")

// apply returns l with update applied: removals, then additions, for a
// partial update, or the additions alone for a whole list. It checks the
// result against the update's checksum, if it has one, and never changes
// l, so a bad update leaves the list as it was.
func (l *prefixList) apply(u HashList) (*prefixList, error) {
	if !slices.IsSorted(u.Additions) || !slices.IsSorted(u.Removals) {
		return nil, errors.New("safebrowsing: update isn't sorted")
	}
	var base []uint32
	if u.Partial {
		if l == nil {
			return nil, errors.New("safebrowsing: partial update for a list there's no copy of")
		}
		base = l.prefixes
	}

	kept := base
	if len(u.Removals) > 0 {
		if !u.Partial {
			return nil, errors.New("safebrowsing: removals in a whole list")
		}
		kept = make([]uint32, 0, len(base))
		next := 0
		for i, p := range base {
			if next < len(u.Removals) && int(u.Removals[next]) == i {
				next++
				for next < len(u.Removals) && int(u.Removals[next]) == i {
					next++ // a repeated index
				}
				continue
			}
			kept = append(kept, p)
		}
		if next != len(u.Removals) {
			return nil, fmt.Errorf("safebrowsing: removal index %d out of range for %d prefixes", u.Removals[next], len(base))
		}
	}

	if u.Partial && len(u.Removals) == 0 && len(u.Additions) == 0 && u.Checksum == nil {
		// Unchanged: the server omits the checksum, meaning the list's
		// current one still holds.
		return &prefixList{version: u.Version, prefixes: base}, nil
	}
	if len(kept)+len(u.Additions) > maxEntries {
		return nil, fmt.Errorf("safebrowsing: list of %d prefixes is too large", len(kept)+len(u.Additions))
	}
	merged := make([]uint32, 0, len(kept)+len(u.Additions))
	i, j := 0, 0
	for i < len(kept) || j < len(u.Additions) {
		var p uint32
		switch {
		case j == len(u.Additions) || (i < len(kept) && kept[i] < u.Additions[j]):
			p, i = kept[i], i+1
		case i == len(kept) || u.Additions[j] < kept[i]:
			p, j = u.Additions[j], j+1
		default: // equal
			p, i, j = kept[i], i+1, j+1
		}
		if n := len(merged); n == 0 || merged[n-1] != p {
			merged = append(merged, p)
		}
	}

	next := &prefixList{version: u.Version, prefixes: merged}
	if u.Checksum != nil && !bytes.Equal(next.checksum(), u.Checksum) {
		return nil, errChecksum
	}
	return next, nil
}

// checksum returns the SHA-256 of the list's sorted prefixes, each as its
// 4 bytes.
func (l *prefixList) checksum() []byte {
	h := sha256.New()
	var b [4]byte
	for _, p := range l.prefixes {
		binary.BigEndian.PutUint32(b[:], p)
		h.Write(b[:])
	}
	return h.Sum(nil)
}

// contains reports whether the list has prefix p.
func (l *prefixList) contains(p uint32) bool {
	if l == nil {
		return false
	}
	_, ok := slices.BinarySearch(l.prefixes, p)
	return ok
}
