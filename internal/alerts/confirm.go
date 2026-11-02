package alerts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Paths of the pages, on the web UI's origin, that confirm an email
// address and unsubscribe one, followed by a code or token. They need no
// sign-in: the code or token is the proof.
const (
	ConfirmPath     = "/alerts/confirm/"
	UnsubscribePath = "/alerts/unsubscribe/"
)

// codeAlphabet is what confirmation codes are written in: Crockford's
// base32, without the letters people confuse with digits (I, L, O, U).
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// codeLength is a confirmation code's length, without its hyphen: ten
// characters of five bits, 50 bits, too many to guess with the few tries
// each scope gets an hour.
const codeLength = 10

// newCode returns a new confirmation code, as "XXXXX-XXXXX".
func newCode() string {
	var b [codeLength]byte
	_, _ = rand.Read(b[:]) // never fails
	out := make([]byte, 0, codeLength+1)
	for i, c := range b {
		if i == codeLength/2 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[c%32]) // 256 is a multiple of 32: uniform
	}
	return string(out)
}

// normalizeCode returns code as it's hashed: upper case, without spaces
// or hyphens, with the letters people mistake for digits read as digits.
// It returns "" for anything that isn't a code.
func normalizeCode(code string) string {
	if len(code) > 64 {
		return ""
	}
	code = strings.Map(func(r rune) rune {
		switch r {
		case '-', ' ', '\t':
			return -1
		case 'o', 'O':
			return '0'
		case 'i', 'I', 'l', 'L':
			return '1'
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		return r
	}, code)
	if len(code) != codeLength || strings.Trim(code, codeAlphabet) != "" {
		return ""
	}
	return code
}

// hashCode returns the SHA-256 of a normalized code, as it's kept.
func hashCode(normalized string) string {
	sum := sha256.Sum256([]byte("doh alerts confirmation\x00" + normalized))
	return hex.EncodeToString(sum[:])
}

// newToken returns a random token for links: 256 bits, base64url.
func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // never fails
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// addEmail adds, as pending, the email address n names to scope, and
// sends it a confirmation code, or sends a pending address a new one.
func (e *Engine) addEmail(ctx context.Context, scope string, n NewDestination, name string) (Destination, error) {
	if e.mailer == nil {
		return Destination{}, fmt.Errorf("%w: email isn't set up on this server; its operator can set it up with --smtp-url", ErrUnavailable)
	}
	addr, err := parseAddress(n.Address)
	if err != nil {
		return Destination{}, err
	}
	url := "mailto:" + addr
	existing, err := e.store.prepareEmail(scope, url)
	if err != nil {
		return Destination{}, err
	}

	// Each address may be sent a few codes a day, by every scope
	// together, and each scope may send a few an hour.
	key := strings.ToLower(addr)
	if e.confirmAddressRate.Limited(key) || e.confirmScopeRate.Limited(scope) {
		return Destination{}, fmt.Errorf("%w: too many confirmation emails have been sent; try again later", ErrRateLimited)
	}
	e.confirmAddressRate.Allow(key)
	e.confirmScopeRate.Allow(scope)

	code := newCode()
	c := &confirmation{hash: hashCode(normalizeCode(code)), expires: time.Now().Add(ConfirmTTL).UTC()}
	var d Destination
	if existing != nil {
		if err := e.store.setConfirmation(scope, existing.ID, c); err != nil {
			return Destination{}, err
		}
		d = *existing
		d.ConfirmBy = c.expires
	} else {
		dest := &destination{
			Destination: Destination{ID: newID(""), Type: Email, Name: name, Created: time.Now().UTC(), CreatedBy: n.CreatedBy, State: Pending},
			url:         url,
			confirm:     c,
		}
		if err := e.store.addDestination(scope, dest); err != nil {
			return Destination{}, err
		}
		d = dest.view()
	}

	link := ""
	if e.words.origin != "" {
		link = strings.TrimSuffix(e.words.origin, "/") + ConfirmPath + strings.ReplaceAll(code, "-", "")
	}
	msg, err := e.confirmEmail(addr, code, link).bytes()
	if err == nil {
		err = e.mailer.send(ctx, addr, msg)
	}
	if err != nil {
		// A new address the code never reached is removed; a pending one
		// keeps waiting, for a code sent before.
		if existing == nil {
			_ = e.store.removeDestination(scope, d.ID)
		}
		e.logger.Warn("alerts: confirmation email not sent", "destination", d.ID, "error", err)
		return Destination{}, fmt.Errorf("%w: the confirmation email couldn't be sent: %v", ErrNotSent, err)
	}
	return d, nil
}

// Confirm confirms scope's pending email address that was sent code,
// returning it: alerts are sent to it from now on. Each code works once,
// within [ConfirmTTL], and each scope may try [ConfirmAttemptsPerScope]
// wrong codes an hour.
func (e *Engine) Confirm(scope, code string) (Destination, error) {
	if e.confirmTries.Limited(scope) {
		return Destination{}, fmt.Errorf("%w: too many wrong codes; try again later", ErrRateLimited)
	}
	_, d, err := e.confirm(func(s string) bool { return s == scope }, code)
	if err != nil {
		e.confirmTries.Allow(scope)
	}
	return d, err
}

// ConfirmAny confirms the pending email address, in any scope, that was
// sent code, as the page the confirmation email links to does, for the
// address's owner, who needn't be able to sign in. It returns the scope
// and the address. Callers must limit how often it's tried.
func (e *Engine) ConfirmAny(code string) (string, Destination, error) {
	return e.confirm(func(string) bool { return true }, code)
}

// confirm confirms the pending address, in a scope allows, sent code.
func (e *Engine) confirm(allows func(string) bool, code string) (string, Destination, error) {
	normalized := normalizeCode(code)
	if normalized == "" {
		return "", Destination{}, fmt.Errorf("%w: a code is ten letters and digits, as XXXXX-XXXXX", ErrNotFound)
	}
	return e.store.confirm(allows, hashCode(normalized), time.Now(), newToken())
}

// Unsubscribe removes the email address whose one-click unsubscribe
// link has token, returning its scope and what it was.
func (e *Engine) Unsubscribe(token string) (string, Destination, error) {
	if token == "" || len(token) > 64 {
		return "", Destination{}, fmt.Errorf("%w: that unsubscribe link isn't for any address", ErrNotFound)
	}
	return e.store.unsubscribe(token)
}

// typeList joins destination types for an error message.
func typeList(types []DestinationType) string {
	s := make([]string, len(types))
	for i, t := range types {
		s[i] = string(t)
	}
	return strings.Join(s, ", ")
}
