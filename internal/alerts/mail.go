package alerts

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Secret is a value, such as a password, that's never shown: printing,
// logging, or formatting it in any way gives "xxxxx".
type Secret string

// redacted is what a [Secret] shows as.
const redacted = "xxxxx"

// String returns "xxxxx".
func (Secret) String() string { return redacted }

// GoString returns "xxxxx", for %#v.
func (Secret) GoString() string { return redacted }

// Format writes "xxxxx", whatever the verb.
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue logs "xxxxx".
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText gives "xxxxx", so a Secret never reaches JSON or text.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Reveal returns the secret itself, for using, never showing.
func (s Secret) Reveal() string { return string(s) }

// MailConfig is how the server's operator sends alerts by email: through
// one SMTP server, for every tenant.
type MailConfig struct {
	// URL is the SMTP server: smtp://user@host:587 (submission, with
	// STARTTLS required) or smtps://user@host:465 (implicit TLS). The
	// user is optional, for servers that take mail without signing in;
	// a password in the URL is refused, since URLs end up in process
	// listings, shell histories, and logs.
	URL string

	// Password is the user's password.
	Password Secret

	// From is the sender, such as "doh <alerts@example.com>".
	From string

	// TLS, if set, is the base TLS configuration, such as root CAs for a
	// private server. The server name always comes from URL, and
	// certificates are always verified.
	TLS *tls.Config

	// LocalName is the name doh greets the server with. It defaults to
	// "localhost".
	LocalName string

	// Dial, if set, connects to the server, for tests. It defaults to a
	// [net.Dialer] with a timeout.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// Mail limits.
const (
	// mailTimeout bounds each email's SMTP conversation.
	mailTimeout = 30 * time.Second

	// maxAddressLength bounds email addresses (RFC 5321, Section 4.5.3.1.3).
	maxAddressLength = 254
)

// mailer sends email through one SMTP server.
type mailer struct {
	host, addr  string
	user        string
	password    Secret
	implicitTLS bool
	loopback    bool
	from        *mail.Address
	domain      string // the sender's domain, for Message-IDs
	tls         *tls.Config
	localName   string
	dial        func(ctx context.Context, network, address string) (net.Conn, error)
}

// CheckMailConfig reports whether c is usable, without connecting. Its
// errors never include the password.
func CheckMailConfig(c MailConfig) error {
	_, err := newMailer(c)
	return err
}

// newMailer returns a mailer for c.
func newMailer(c MailConfig) (*mailer, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("alerts: the SMTP URL is smtp://[user@]host[:587] or smtps://[user@]host[:465]")
	}
	if _, has := u.User.Password(); has {
		return nil, errors.New("alerts: the SMTP URL can't hold a password; give it in a file (--smtp-password-file) or DOH_SMTP_PASSWORD")
	}
	if strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("alerts: the SMTP URL is only a scheme, user, host, and port")
	}
	m := &mailer{host: u.Hostname(), password: c.Password, localName: c.LocalName, dial: c.Dial}
	if u.User != nil {
		m.user = u.User.Username()
	}
	port := u.Port()
	switch u.Scheme {
	case "smtp":
		port = cmp.Or(port, "587")
	case "smtps":
		port = cmp.Or(port, "465")
		m.implicitTLS = true
	default:
		return nil, fmt.Errorf("alerts: SMTP URL scheme %q must be smtp (STARTTLS) or smtps (implicit TLS)", u.Scheme)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("alerts: invalid SMTP port %q", port)
	}
	m.addr = net.JoinHostPort(m.host, port)
	a, err := netip.ParseAddr(m.host)
	m.loopback = strings.EqualFold(m.host, "localhost") || err == nil && a.IsLoopback()

	switch {
	case m.user == "" && c.Password != "":
		return nil, errors.New("alerts: an SMTP password needs a user in the URL, as smtp://user@host:587")
	case m.user != "" && c.Password == "":
		return nil, fmt.Errorf("alerts: the SMTP user %s needs a password: give it in a file (--smtp-password-file) or DOH_SMTP_PASSWORD", m.user)
	}

	from, err := mail.ParseAddress(c.From)
	if err != nil || !isASCII(from.Address) {
		return nil, errors.New("alerts: the sender (--smtp-from) is an email address, such as \"doh <alerts@example.com>\"")
	}
	m.from = from
	_, m.domain, _ = strings.Cut(from.Address, "@")

	if c.TLS != nil {
		m.tls = c.TLS.Clone()
	} else {
		m.tls = new(tls.Config)
	}
	m.tls.ServerName = m.host
	m.tls.InsecureSkipVerify = false
	m.tls.MinVersion = max(m.tls.MinVersion, tls.VersionTLS12)

	if m.localName == "" {
		m.localName = "localhost"
	}
	if m.dial == nil {
		d := &net.Dialer{Timeout: dialTimeout}
		m.dial = d.DialContext
	}
	return m, nil
}

// isASCII reports whether s is printable ASCII.
func isASCII(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < ' ' || r > '~' })
}

// parseAddress checks an email destination's address: one bare address,
// in ASCII, at a domain with a dot, returned as doh keeps it.
func parseAddress(raw string) (string, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "mailto:"))
	if raw == "" || len(raw) > maxAddressLength || !isASCII(raw) {
		return "", fmt.Errorf("%w: an email destination is an address of at most %d characters, such as alex@example.com", ErrInvalid, maxAddressLength)
	}
	a, err := mail.ParseAddress(raw)
	if err != nil || a.Name != "" || a.Address != raw {
		return "", fmt.Errorf("%w: %q isn't an email address, such as alex@example.com", ErrInvalid, raw)
	}
	local, domain, _ := strings.Cut(a.Address, "@")
	if local == "" || !strings.Contains(strings.Trim(domain, "."), ".") || strings.ContainsAny(domain, "[]") {
		return "", fmt.Errorf("%w: %q isn't an address on the internet", ErrInvalid, raw)
	}
	// Domains are case-insensitive; local parts, strictly, aren't.
	return local + "@" + strings.ToLower(domain), nil
}

// send sends msg to to, once. A refusal that retrying won't change (a
// 5xx reply, or a server that won't encrypt) is permanent.
func (m *mailer) send(ctx context.Context, to string, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, mailTimeout)
	defer cancel()

	conn, err := m.dial(ctx, "tcp", m.addr)
	if err != nil {
		return fmt.Errorf("connecting to the mail server: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if m.implicitTLS {
		tc := tls.Client(conn, m.tls)
		if err := tc.HandshakeContext(ctx); err != nil {
			return permanentError{fmt.Errorf("the mail server's TLS: %w", err)}
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return smtpError("greeting", err)
	}
	defer c.Close()
	if err := c.Hello(m.localName); err != nil {
		return smtpError("EHLO", err)
	}
	if !m.implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(m.tls); err != nil {
				return permanentError{fmt.Errorf("the mail server's TLS: %w", err)}
			}
		} else if !m.loopback {
			// Only a server on this machine may be spoken to in the clear.
			return permanentError{errors.New("the mail server doesn't offer STARTTLS, and doh won't send mail or a password unencrypted")}
		}
	}
	if m.user != "" {
		if ok, mechs := c.Extension("AUTH"); !ok || !strings.Contains(" "+strings.ToUpper(mechs)+" ", " PLAIN ") {
			return permanentError{errors.New("the mail server doesn't offer AUTH PLAIN")}
		}
		// PlainAuth itself refuses to send the password unencrypted to
		// anything but localhost.
		if err := c.Auth(smtp.PlainAuth("", m.user, m.password.Reveal(), m.host)); err != nil {
			return smtpError("signing in", err)
		}
	}
	if err := c.Mail(m.from.Address); err != nil {
		return smtpError("MAIL FROM", err)
	}
	if err := c.Rcpt(to); err != nil {
		return smtpError("RCPT TO", err)
	}
	w, err := c.Data()
	if err != nil {
		return smtpError("DATA", err)
	}
	if _, err := w.Write(msg); err != nil {
		return smtpError("sending the message", err)
	}
	if err := w.Close(); err != nil {
		return smtpError("sending the message", err)
	}
	_ = c.Quit()
	return nil
}

// smtpError describes a failed SMTP step. A 5xx reply is permanent; 4xx
// replies and network errors may not last.
func smtpError(step string, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		err = fmt.Errorf("the mail server refused %s: %d %s", step, te.Code, te.Msg)
		if te.Code >= 500 {
			return permanentError{err}
		}
		return err
	}
	return fmt.Errorf("the mail server, at %s: %w", step, err)
}

// newMessageID returns a Message-ID for a message from domain.
func newMessageID(domain string) string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // never fails
	return fmt.Sprintf("<%x@%s>", b, domain)
}
