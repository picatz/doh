package signin

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// pendingLifetime bounds sessions that haven't finished signing in.
const pendingLifetime = 10 * time.Minute

// cookieName returns the session cookie's name: with the __Host- prefix
// when every origin is HTTPS, so browsers only accept it as Secure,
// host-only, and for the whole site ([RFC 6265bis, Section 4.1.3.2]).
//
// [RFC 6265bis, Section 4.1.3.2]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.3.2
func (s *Service) cookieName() string {
	if s.secure {
		return "__Host-doh-session"
	}
	return "doh-session"
}

// Session returns the session r's cookie names, if it's live, and
// refreshes its idle timer. The session may be pending.
func (s *Service) Session(r *http.Request) (Session, bool) {
	c, err := r.Cookie(s.cookieName())
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	key := sha256.Sum256([]byte(c.Value))
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[key]
	switch {
	case !ok:
		return Session{}, false
	case !now.Before(sess.Expires) || now.Sub(sess.lastSeen) >= s.config.IdleTimeout:
		delete(s.sessions, key)
		return Session{}, false
	}
	sess.lastSeen = now
	return *sess, true
}

// binding returns the WebAuthn ceremony binding for r's session: a
// server-held value derived from its cookie, so a ceremony can only be
// finished by the session that began it.
func (s *Service) binding(r *http.Request) (string, bool) {
	c, err := r.Cookie(s.cookieName())
	if err != nil || c.Value == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte("doh signin ceremony binding\x00" + c.Value))
	return hex.EncodeToString(sum[:]), true
}

// startSession begins a new session, replacing any r already has, so a
// session's ID changes whenever what it may do does (preventing session
// fixation), and sets its cookie on w.
func (s *Service) startSession(w http.ResponseWriter, r *http.Request, sess Session) error {
	token, err := randomToken()
	if err != nil {
		return err
	}

	now := s.now()
	sess.Created, sess.lastSeen = now, now
	sess.Expires = now.Add(s.config.Lifetime)
	if sess.Pending {
		sess.Expires = now.Add(pendingLifetime)
	}

	s.mu.Lock()
	if c, err := r.Cookie(s.cookieName()); err == nil {
		delete(s.sessions, sha256.Sum256([]byte(c.Value)))
	}
	s.sweep(now)
	// Pending sessions can be started by anyone, so they have their own
	// budget, and only ever displace each other: a flood of them can't sign
	// out the people who finished signing in.
	if n, limit := s.count(sess.Pending), sessionLimit(sess.Pending); n >= limit {
		s.evictOldest(sess.Pending)
	}
	s.sessions[sha256.Sum256([]byte(token))] = &sess
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    token,
		Path:     "/",
		Expires:  sess.Expires,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	// The cookie is the new session; make sure r carries it for the rest
	// of this request.
	r.Header.Del("Cookie")
	r.AddCookie(&http.Cookie{Name: s.cookieName(), Value: token})
	return nil
}

// endSession ends r's session, if any, and clears its cookie.
func (s *Service) endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		s.mu.Lock()
		delete(s.sessions, sha256.Sum256([]byte(c.Value)))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   s.secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// endSessions ends every session of person. s.mu must be held.
func (s *Service) endSessions(person string) {
	for k, sess := range s.sessions {
		if sess.Person == person {
			delete(s.sessions, k)
		}
	}
}

// sweep removes expired sessions. s.mu must be held.
func (s *Service) sweep(now time.Time) {
	for k, sess := range s.sessions {
		if !now.Before(sess.Expires) || now.Sub(sess.lastSeen) >= s.config.IdleTimeout {
			delete(s.sessions, k)
		}
	}
}

// sessionLimit returns how many pending, or complete, sessions may exist.
func sessionLimit(pending bool) int {
	if pending {
		return maxPendingSessions
	}
	return maxSessions
}

// count returns the number of pending, or complete, sessions. s.mu must be
// held.
func (s *Service) count(pending bool) int {
	n := 0
	for _, sess := range s.sessions {
		if sess.Pending == pending {
			n++
		}
	}
	return n
}

// evictOldest removes the least recently used pending, or complete,
// session. s.mu must be held.
func (s *Service) evictOldest(pending bool) {
	var (
		oldest [sha256.Size]byte
		seen   time.Time
		found  bool
	)
	for k, sess := range s.sessions {
		if sess.Pending == pending && (!found || sess.lastSeen.Before(seen)) {
			oldest, seen, found = k, sess.lastSeen, true
		}
	}
	if found {
		delete(s.sessions, oldest)
	}
}
