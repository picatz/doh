package doq

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/quic"
)

// clientCloseGrace bounds how long Close waits for its connection's close
// to be sent.
const clientCloseGrace = 100 * time.Millisecond

// Client sends queries to a DoQ server over one connection, reused across
// queries and reopened when it closes. It's safe for concurrent use.
type Client struct {
	// Addr is the server's address, as host:port.
	Addr string

	// TLSConfig configures the connection. Its ServerName defaults to
	// Addr's host. The client uses a copy that requires TLS 1.3 and offers
	// only the "doq" protocol.
	TLSConfig *tls.Config

	mu       sync.Mutex
	endpoint *quic.Endpoint
	conn     *quic.Conn
}

// Exchange sends query and returns the server's response, with its ID set
// to the query's: on the wire, DoQ messages carry ID zero ([RFC 9250,
// Section 4.2.1]). Queries that use EDNS(0) are padded ([RFC 8467]).
//
// If the reused connection turns out to be closed, the query is sent once
// more on a new connection.
//
// [RFC 9250, Section 4.2.1]: https://www.rfc-editor.org/rfc/rfc9250.html#section-4.2.1
// [RFC 8467]: https://www.rfc-editor.org/rfc/rfc8467.html
func (c *Client) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	q := query.Copy()
	q.Id = 0
	if opt := q.IsEdns0(); opt != nil {
		// DoQ forbids edns-tcp-keepalive; QUIC manages the connection.
		opt.Option = deleteKeepalive(opt.Option)
	}
	pad(q, queryBlock)

	conn, reused, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := exchange(ctx, conn, q)
	if err != nil && reused && ctx.Err() == nil {
		// The server may have closed the idle connection: try a fresh one.
		c.forget(conn)
		if conn, _, err = c.connection(ctx); err != nil {
			return nil, err
		}
		resp, err = exchange(ctx, conn, q)
	}
	if err != nil {
		c.forget(conn)
		return nil, err
	}

	resp.Id = query.Id
	return resp, nil
}

// exchange sends q on a new stream of conn and reads the response.
func exchange(ctx context.Context, conn *quic.Conn, q *dns.Msg) (*dns.Msg, error) {
	stream, err := conn.NewStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("doq: opening stream: %w", err)
	}
	defer stream.Close()
	stream.SetReadContext(ctx)
	stream.SetWriteContext(ctx)

	if err := writeMessage(stream, q); err != nil {
		return nil, fmt.Errorf("doq: sending query: %w", err)
	}
	// Ending the stream's sending side tells the server the query is
	// complete (RFC 9250, Section 4.2).
	if err := stream.CloseWrite(); err != nil {
		return nil, fmt.Errorf("doq: sending query: %w", err)
	}

	resp, err := readMessage(stream)
	if err != nil {
		return nil, err
	}
	if !resp.Response {
		return nil, fmt.Errorf("%w: server sent a query", errProtocol)
	}
	return resp, nil
}

// connection returns the client's connection, dialing one if it has none,
// and reports whether it was reused.
func (c *Client) connection(ctx context.Context) (*quic.Conn, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn, true, nil
	}

	if c.endpoint == nil {
		// A client-only endpoint, on an ephemeral port.
		endpoint, err := quic.Listen("udp", ":0", nil)
		if err != nil {
			return nil, false, fmt.Errorf("doq: %w", err)
		}
		c.endpoint = endpoint
	}

	config := &tls.Config{}
	if c.TLSConfig != nil {
		config = c.TLSConfig.Clone()
	}
	config.MinVersion = tls.VersionTLS13
	config.NextProtos = []string{ALPN}
	if config.ServerName == "" {
		if host, _, err := net.SplitHostPort(c.Addr); err == nil {
			config.ServerName = host
		}
	}

	conn, err := c.endpoint.Dial(ctx, "udp", c.Addr, &quic.Config{TLSConfig: config, MaxIdleTimeout: DefaultIdleTimeout})
	if err != nil {
		return nil, false, fmt.Errorf("doq: connecting to %s: %w", c.Addr, err)
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != ALPN {
		conn.Abort(closeError(CodeProtocolError, "doq: no application protocol"))
		return nil, false, fmt.Errorf("doq: %s doesn't speak DoQ (negotiated %q)", c.Addr, p)
	}
	c.conn = conn
	return conn, false, nil
}

// forget drops conn, if it's still the client's connection, so the next
// query dials a new one.
func (c *Client) forget(conn *quic.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == conn {
		c.conn = nil
		conn.Abort(nil)
	}
}

// Close closes the client's connection and endpoint.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Abort(nil)
		c.conn = nil
	}
	if c.endpoint == nil {
		return nil
	}
	// Abort has already told the server the connection is closing; wait
	// only long enough for that to leave, not for acknowledgements, which
	// a half-open or unreachable server never sends.
	ctx, cancel := context.WithTimeout(context.Background(), clientCloseGrace)
	defer cancel()
	err := c.endpoint.Close(ctx)
	c.endpoint = nil
	if errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// String describes the client as an upstream URL.
func (c *Client) String() string { return "quic://" + c.Addr }
