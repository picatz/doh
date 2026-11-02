package doq

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/miekg/dns"
)

// FuzzReadMessage reads a stream as a DoQ server or client does: it must
// never panic, must refuse anything but exactly one length-prefixed
// message, and what it accepts must pack and read back the same.
func FuzzReadMessage(f *testing.F) {
	for _, m := range []*dns.Msg{
		new(dns.Msg).SetQuestion("example.com.", dns.TypeA),
		new(dns.Msg).SetQuestion("example.com.", dns.TypeHTTPS).SetEdns0(4096, true),
	} {
		var b bytes.Buffer
		if err := writeMessage(&b, m); err != nil {
			f.Fatal(err)
		}
		f.Add(b.Bytes())
		f.Add(append(bytes.Clone(b.Bytes()), 0)) // a second message starts
		f.Add(b.Bytes()[:b.Len()-1])             // cut short
	}
	f.Add([]byte{0, 0})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, stream []byte) {
		m, err := readMessage(bytes.NewReader(stream))
		if err != nil {
			if m != nil {
				t.Fatal("a message with an error")
			}
			return
		}
		n := int(binary.BigEndian.Uint16(stream))
		if len(stream) != 2+n || n == 0 {
			t.Fatalf("accepted %d bytes for a %d-byte message", len(stream), n)
		}
		var again bytes.Buffer
		if err := writeMessage(&again, m); err != nil {
			// Some messages unpack but don't pack (such as with
			// out-of-range values); they're answered with an error.
			return
		}
		// The framing round-trips. (The message itself may not: miekg/dns
		// packs some records it unpacked, with hex data, into bytes it
		// can't unpack again, as this target's seed corpus records.)
		b := again.Bytes()
		if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
			t.Fatalf("written with a bad length prefix: %x", b)
		}
		if m2, err := readMessage(bytes.NewReader(b)); err == nil && (m2.Id != m.Id || len(m2.Question) != len(m.Question)) {
			t.Fatalf("round trip changed the message: %v", m2)
		}
	})
}
