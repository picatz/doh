package alerts

import (
	"bytes"
	"fmt"
	"html/template"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// message is an email to send: a text and an HTML part with the same
// words.
type message struct {
	from    *mail.Address
	to      string
	domain  string
	date    time.Time
	subject string

	// title, paragraphs, and footer are the words; link, if any, is the
	// one thing to open, labeled button.
	title      string
	paragraphs []string
	code       string // a paragraph that's a code to read out, shown large
	link       string
	button     string
	footer     []string

	// unsubscribe, if set, is a URL that stops these emails in one click
	// (RFC 8058).
	unsubscribe string
}

// maxSubject bounds a subject, in runes, so it stays readable and its
// header short.
const maxSubject = 200

// bytes returns m as an RFC 5322 message, with CRLF line endings, MIME
// headers, and multipart/alternative text and HTML parts, each
// quoted-printable.
func (m message) bytes() ([]byte, error) {
	var b bytes.Buffer
	header := func(name, value string) { b.WriteString(fold(name + ": " + value)) }

	header("From", m.from.String()) // encodes a display name that isn't ASCII
	header("To", "<"+m.to+">")
	header("Subject", encodeHeader(m.subject))
	header("Date", m.date.Format(time.RFC1123Z))
	header("Message-ID", newMessageID(m.domain))
	header("MIME-Version", "1.0")
	// Automatic, so out-of-office replies aren't sent back (RFC 3834).
	header("Auto-Submitted", "auto-generated")
	header("X-Auto-Response-Suppress", "All")
	if m.unsubscribe != "" {
		header("List-Unsubscribe", "<"+m.unsubscribe+">")
		header("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
	}

	html, err := m.html()
	if err != nil {
		return nil, err
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	header("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
	b.WriteString("\r\n")

	for _, part := range []struct{ ctype, content string }{
		{"text/plain; charset=utf-8", m.text()},
		{"text/html; charset=utf-8", html},
	} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.ctype},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(part.content)); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	b.Write(body.Bytes())
	return b.Bytes(), nil
}

// text returns the plain text part.
func (m message) text() string {
	var b strings.Builder
	b.WriteString(m.title + "\n\n")
	for _, p := range m.paragraphs {
		b.WriteString(p + "\n\n")
	}
	if m.link != "" && !strings.Contains(strings.Join(m.paragraphs, "\n"), m.link) {
		b.WriteString(m.button + ": " + m.link + "\n\n")
	}
	if len(m.footer) > 0 {
		b.WriteString("-- \n")
		for _, f := range m.footer {
			b.WriteString(f + "\n")
		}
	}
	return strings.ReplaceAll(b.String(), "\n", "\r\n")
}

// segment is a piece of a paragraph: text, or a link.
type segment struct {
	Text, Link string
	Break      bool
}

// segments splits p into text and its links to link, and lines.
func segments(p, link string) []segment {
	var out []segment
	for i, line := range strings.Split(p, "\n") {
		if i > 0 {
			out = append(out, segment{Break: true})
		}
		for link != "" {
			before, after, ok := strings.Cut(line, link)
			if !ok {
				break
			}
			out = append(out, segment{Text: before}, segment{Text: link, Link: link})
			line = after
		}
		out = append(out, segment{Text: line})
	}
	return out
}

// htmlTemplate is the HTML part: one column, system fonts, inline styles
// only (mail clients drop style sheets), and no images, so nothing loads
// from anywhere. It sets no text or page colors, so mail clients' light
// and dark modes apply as they would to their own text; the only colors
// are the button's, white on doh's glaze, legible in either.
var htmlTemplate = template.Must(template.New("email").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{{.Title}}</title>
</head>
<body style="margin:0;padding:0;">
<div role="article" aria-roledescription="email" aria-label="{{.Title}}" lang="en" style="max-width:560px;margin:0 auto;padding:28px 20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:16px;line-height:1.55;">
<p style="margin:0 0 20px;font-size:15px;font-weight:700;letter-spacing:.01em;"><span aria-hidden="true" style="display:inline-block;width:8px;height:8px;border:5px solid #d6336c;border-radius:50%;vertical-align:-4px;margin-right:8px;"></span>doh</p>
<h1 style="margin:0 0 14px;font-size:22px;line-height:1.3;font-weight:700;">{{.Title}}</h1>
{{range .Paragraphs}}{{if .Code}}<p style="margin:0 0 16px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:26px;font-weight:700;letter-spacing:.12em;">{{.Code}}</p>
{{else}}<p style="margin:0 0 16px;">{{range .Segments}}{{if .Break}}<br>{{else if .Link}}<a href="{{.Link}}" style="word-break:break-all;">{{.Text}}</a>{{else}}{{.Text}}{{end}}{{end}}</p>
{{end}}
{{end}}{{if .Link}}<p style="margin:24px 0;"><a href="{{.Link}}" style="display:inline-block;padding:12px 22px;border-radius:999px;background-color:#c2255c;color:#ffffff;text-decoration:none;font-weight:600;">{{.Button}}</a></p>
{{end}}{{if .Footer}}<hr style="border:0;border-top:1px solid rgba(128,128,128,.35);margin:28px 0 14px;">
{{range .Footer}}<p style="margin:0 0 6px;font-size:13px;opacity:.8;">{{range .}}{{if .Link}}<a href="{{.Link}}">{{.Text}}</a>{{else}}{{.Text}}{{end}}{{end}}</p>
{{end}}{{end}}</div>
</body>
</html>
`))

// paragraph is a paragraph of the HTML part: text and links, or a code.
type paragraph struct {
	Segments []segment
	Code     string
}

// html returns the HTML part.
func (m message) html() (string, error) {
	data := struct {
		Title, Link, Button string
		Paragraphs          []paragraph
		Footer              [][]segment
	}{Title: m.title, Link: m.link, Button: m.button}
	for _, p := range m.paragraphs {
		if m.code != "" && p == m.code {
			data.Paragraphs = append(data.Paragraphs, paragraph{Code: p})
			continue
		}
		data.Paragraphs = append(data.Paragraphs, paragraph{Segments: segments(p, m.link)})
	}
	for _, f := range m.footer {
		data.Footer = append(data.Footer, segments(f, m.unsubscribe))
	}
	var b strings.Builder
	if err := htmlTemplate.Execute(&b, data); err != nil {
		return "", err
	}
	return strings.ReplaceAll(b.String(), "\n", "\r\n"), nil
}

// encodeHeader encodes s for a header: as itself if it's printable
// ASCII, or as RFC 2047 encoded words. Control characters, which could
// end the header early, become spaces first, and s is cut to
// [maxSubject] runes.
func encodeHeader(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxSubject {
		s = string(r[:maxSubject-1]) + "…"
	}
	return mime.QEncoding.Encode("utf-8", s)
}

// fold folds a header line at spaces so lines stay within 78 characters
// where they can (RFC 5322, Section 2.2.3), ending it with CRLF. Encoded
// words are separated by spaces, so they fold between words.
func fold(line string) string {
	const limit = 78
	var b strings.Builder
	n := 0
	for i, word := range strings.Split(line, " ") {
		switch {
		case i == 0:
		case n+1+len(word) > limit:
			b.WriteString("\r\n")
			n = 0
			fallthrough
		default:
			b.WriteByte(' ')
			n++
		}
		b.WriteString(word)
		n += len(word)
	}
	b.WriteString("\r\n")
	return b.String()
}

// alertEmail returns the email of alert a to an email destination.
func (e *Engine) alertEmail(to, unsubscribe string, a Alert) message {
	m := message{
		from: e.mailer.from, to: to, domain: e.mailer.domain, date: time.Now(),
		subject: a.Title, title: a.Title,
		paragraphs: []string{a.Body},
		link:       a.Details.Link, button: "Open in doh",
	}
	where := "doh"
	if e.words.origin != "" {
		where = "doh at " + e.words.origin
	}
	m.footer = []string{fmt.Sprintf("You get these because this address was confirmed to receive alerts from %s.", where)}
	if unsubscribe != "" {
		m.unsubscribe = unsubscribe
		m.footer = append(m.footer, "To stop them, unsubscribe: "+unsubscribe)
	} else {
		m.footer = append(m.footer, `To stop them, ask whoever manages doh to remove this address ("doh alerts remove").`)
	}
	return m
}

// confirmEmail returns the email asking to to confirm it wants alerts,
// with code, or link, which opens a page that takes it. It says nothing
// a tenant chose (its name, or the destination's), so the server can't
// be made to send strangers someone else's words.
func (e *Engine) confirmEmail(to, code, link string) message {
	where := "a doh server"
	if e.words.origin != "" {
		where = "the doh server at " + e.words.origin
	}
	how := "If you want them, give whoever set it up this code:"
	if link != "" {
		how = "If you want them, open " + link + " and press Confirm, or give whoever set it up this code:"
	}
	return message{
		from: e.mailer.from, to: to, domain: e.mailer.domain, date: time.Now(),
		subject: "Confirm alerts from doh",
		title:   "Confirm alerts from doh",
		paragraphs: []string{
			fmt.Sprintf("Someone who manages %s asked to send its alerts, about threats it blocks, new devices, and lookups that fail, to %s. Nothing is sent until this address is confirmed.", where, to),
			how,
			code,
			fmt.Sprintf("The code works once, for %d hours. If you didn't expect this, ignore it: no alerts will be sent here.", int(ConfirmTTL.Hours())),
		},
		code:   code,
		link:   link,
		button: "Confirm alerts",
		footer: []string{"doh sent this once, because an address was added; it sends no more unless the address is added again."},
	}
}
