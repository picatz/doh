// Package doq implements DNS over Dedicated QUIC Connections (DoQ, [RFC
// 9250]): a server that answers queries, and a client that sends them.
//
// Each query travels on its own bidirectional QUIC stream, as a DNS
// message with a two-byte length prefix, and its response comes back on
// the same stream. Many queries share one connection without blocking each
// other, unlike DNS over TCP or TLS, where a lost packet delays every
// query behind it.
//
// The package is built on golang.org/x/net/quic, which is experimental,
// and keeps it out of its own API, so changes there stay contained here.
//
// [RFC 9250]: https://www.rfc-editor.org/rfc/rfc9250.html
package doq

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/miekg/dns"
	"golang.org/x/net/quic"
)

// ALPN is DoQ's TLS application protocol identifier ([RFC 9250, Section
// 4.1.1]).
//
// [RFC 9250, Section 4.1.1]: https://www.rfc-editor.org/rfc/rfc9250.html#section-4.1.1
const ALPN = "doq"

// DefaultPort is DoQ's UDP port ([RFC 9250, Section 4.1.1]).
//
// [RFC 9250, Section 4.1.1]: https://www.rfc-editor.org/rfc/rfc9250.html#section-4.1.1
const DefaultPort = "853"

// Error codes DoQ endpoints use to close streams and connections ([RFC
// 9250, Section 4.3]).
//
// [RFC 9250, Section 4.3]: https://www.rfc-editor.org/rfc/rfc9250.html#section-4.3
const (
	CodeNoError          uint64 = 0x0
	CodeInternalError    uint64 = 0x1
	CodeProtocolError    uint64 = 0x2
	CodeRequestCancelled uint64 = 0x3
	CodeExcessiveLoad    uint64 = 0x4
)

// errProtocol reports a peer breaking DoQ's rules, which ends the
// connection with [CodeProtocolError].
var errProtocol = errors.New("doq: protocol error")

// readMessage reads one length-prefixed DNS message from r, then requires
// the stream to end, since a stream carries exactly one message each way
// ([RFC 9250, Section 4.2]).
//
// [RFC 9250, Section 4.2]: https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2
func readMessage(r io.Reader) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("doq: reading message length: %w", err)
	}
	n := binary.BigEndian.Uint16(prefix[:])
	if n == 0 {
		return nil, fmt.Errorf("%w: empty message", errProtocol)
	}

	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("doq: reading message: %w", err)
	}

	var extra [1]byte
	switch _, err := r.Read(extra[:]); {
	case err == io.EOF:
	case err != nil:
		return nil, fmt.Errorf("doq: reading message: %w", err)
	default:
		return nil, fmt.Errorf("%w: more than one message on a stream", errProtocol)
	}

	var m dns.Msg
	if err := m.Unpack(b); err != nil {
		return nil, fmt.Errorf("%w: %v", errProtocol, err)
	}
	return &m, nil
}

// writeMessage writes m to w with its two-byte length prefix.
func writeMessage(w io.Writer, m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return fmt.Errorf("doq: packing message: %w", err)
	}
	if len(b) > dns.MaxMsgSize {
		return fmt.Errorf("doq: message of %d bytes is too large", len(b))
	}
	_, err = w.Write(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(b)), uint16(len(b))))
	if err == nil {
		_, err = w.Write(b)
	}
	return err
}

// hasKeepalive reports whether m carries the edns-tcp-keepalive option,
// which DoQ forbids ([RFC 9250, Section 5.5.2]).
//
// [RFC 9250, Section 5.5.2]: https://www.rfc-editor.org/rfc/rfc9250.html#section-5.5.2
func hasKeepalive(m *dns.Msg) bool {
	opt := m.IsEdns0()
	return opt != nil && slices.ContainsFunc(opt.Option, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0TCPKEEPALIVE })
}

// Padding block sizes ([RFC 8467, Section 4.1]): queries are padded to a
// multiple of 128 bytes, and responses to a multiple of 468, so sizes
// reveal little about names.
//
// [RFC 8467, Section 4.1]: https://www.rfc-editor.org/rfc/rfc8467.html#section-4.1
const (
	queryBlock    = 128
	responseBlock = 468
)

// pad adds EDNS(0) padding ([RFC 7830]) to m, if it uses EDNS(0), so its
// packed size is a multiple of block. Existing padding is replaced.
//
// [RFC 7830]: https://www.rfc-editor.org/rfc/rfc7830.html
func pad(m *dns.Msg, block int) {
	opt := m.IsEdns0()
	if opt == nil {
		return
	}
	opt.Option = slices.DeleteFunc(opt.Option, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0PADDING })

	// The padding option itself takes four bytes of header.
	n := m.Len() + 4
	if rem := n % block; rem != 0 {
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, block-rem)})
	} else {
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{})
	}
}

// padded reports whether m carries EDNS(0) padding, so a response to it
// should be padded too ([RFC 8467, Section 4.1]).
//
// [RFC 8467, Section 4.1]: https://www.rfc-editor.org/rfc/rfc8467.html#section-4.1
func padded(m *dns.Msg) bool {
	opt := m.IsEdns0()
	return opt != nil && slices.ContainsFunc(opt.Option, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0PADDING })
}

// closeError is the connection close error for a DoQ error code.
func closeError(code uint64, reason string) error {
	return &quic.ConnectionCloseError{Code: code, Reason: reason}
}

// deleteKeepalive removes edns-tcp-keepalive options.
func deleteKeepalive(opts []dns.EDNS0) []dns.EDNS0 {
	return slices.DeleteFunc(opts, func(o dns.EDNS0) bool { return o.Option() == dns.EDNS0TCPKEEPALIVE })
}
