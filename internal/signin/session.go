package signin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"
)

// pendingLifetime bounds sessions that haven't finished signing in.
const pendingLifetime = 10 * time.Minute

// touchInterval is how often a session's last use is recorded: its idle
// timer is kept to the minute, so a busy UI doesn't write on every
// request.
const touchInterval = time.Minute

// SessionID identifies a stored session: the SHA-256 of its cookie's
// value, so whoever reads the store can't use what's in it.
type SessionID [sha256.Size]byte

// StoredSession is a session as a [Sessions] store keeps it.
type StoredSession struct {
	Session

	// LastSeen is when the session was last used, to the minute, for its
	// idle timeout.
	LastSeen time.Time
}

// Sessions keeps browser sessions. The default keeps them in memory; a
// database lets them survive restarts and be shared by replicas.
// Implementations must be safe for concurrent use.
type Sessions interface {
	// Get returns the session stored under id, whether or not it has
	// expired: the [Service] decides that.
	Get(ctx context.Context, id SessionID) (StoredSession, bool, error)

	// Put stores sess under id, first removing the session under
	// replaced, if any. If limit sessions as pending as sess already
	// exist, it first removes the least recently seen of them, so pending
	// sessions, which anyone can start, only ever displace each other.
	Put(ctx context.Context, id, replaced SessionID, sess StoredSession, limit int) error

	// Touch records that the session under id was used at t.
	Touch(ctx context.Context, id SessionID, t time.Time) error

	// Delete removes the session under id, if there is one.
	Delete(ctx context.Context, id SessionID) error

	// DeletePerson removes every session of person.
	DeletePerson(ctx context.Context, person string) error

	// Sweep removes sessions that expired by now, or that haven't been
	// used for idle.
	Sweep(ctx context.Context, now time.Time, idle time.Duration) error
}

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

// sessionID returns the ID r's cookie names, if it has one.
func (s *Service) sessionID(r *http.Request) (SessionID, bool) {
	c, err := r.Cookie(s.cookieName())
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return SessionID{}, false
	}
	return SessionID(sha256.Sum256([]byte(c.Value))), true
}

// Session returns the session r's cookie names, if it's live, and
// refreshes its idle timer. The session may be pending.
func (s *Service) Session(r *http.Request) (Session, bool) {
	id, ok := s.sessionID(r)
	if !ok {
		return Session{}, false
	}
	ctx := r.Context()
	sess, ok, err := s.sessions.Get(ctx, id)
	if err != nil {
		s.logger.ErrorContext(ctx, "signin: reading a session", slog.Any("error", err))
		return Session{}, false
	}
	if !ok {
		return Session{}, false
	}
	now := s.now()
	if !now.Before(sess.Expires) || now.Sub(sess.LastSeen) >= s.config.IdleTimeout || !s.personExists(sess.Person) {
		if err := s.sessions.Delete(ctx, id); err != nil {
			s.logger.WarnContext(ctx, "signin: removing an expired session", slog.Any("error", err))
		}
		return Session{}, false
	}
	if now.Sub(sess.LastSeen) >= touchInterval {
		if err := s.sessions.Touch(ctx, id, now); err != nil {
			s.logger.WarnContext(ctx, "signin: recording a session's use", slog.Any("error", err))
		}
	}
	return sess.Session, true
}

// personExists reports whether a session's person, if it has one, can
// still sign in. Their sessions are removed with them, but a store's
// removal may fail or, shared by replicas, lag; this makes it certain.
func (s *Service) personExists(person string) bool {
	if person == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.people, func(p Person) bool { return p.ID == person })
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
	sess.Created = now
	sess.Expires = now.Add(s.config.Lifetime)
	if sess.Pending {
		sess.Expires = now.Add(pendingLifetime)
	}

	ctx := r.Context()
	replaced, _ := s.sessionID(r)
	if err := s.sessions.Sweep(ctx, now, s.config.IdleTimeout); err != nil {
		s.logger.WarnContext(ctx, "signin: removing expired sessions", slog.Any("error", err))
	}
	// Pending sessions can be started by anyone, so they have their own
	// budget, and only ever displace each other: a flood of them can't sign
	// out the people who finished signing in.
	id := SessionID(sha256.Sum256([]byte(token)))
	if err := s.sessions.Put(ctx, id, replaced, StoredSession{Session: sess, LastSeen: now}, sessionLimit(sess.Pending)); err != nil {
		return err
	}

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
	if id, ok := s.sessionID(r); ok {
		if err := s.sessions.Delete(r.Context(), id); err != nil {
			s.logger.ErrorContext(r.Context(), "signin: ending a session", slog.Any("error", err))
		}
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

// sessionLimit returns how many pending, or complete, sessions may exist.
func sessionLimit(pending bool) int {
	if pending {
		return maxPendingSessions
	}
	return maxSessions
}

// memorySessions keeps sessions in memory: the default [Sessions].
type memorySessions struct {
	mu       sync.Mutex
	sessions map[SessionID]StoredSession
}

func newMemorySessions() *memorySessions {
	return &memorySessions{sessions: make(map[SessionID]StoredSession)}
}

func (m *memorySessions) Get(_ context.Context, id SessionID) (StoredSession, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	return sess, ok, nil
}

func (m *memorySessions) Put(_ context.Context, id, replaced SessionID, sess StoredSession, limit int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, replaced)
	if m.count(sess.Pending) >= limit {
		m.evictOldest(sess.Pending)
	}
	m.sessions[id] = sess
	return nil
}

func (m *memorySessions) Touch(_ context.Context, id SessionID, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess, ok := m.sessions[id]; ok {
		sess.LastSeen = t
		m.sessions[id] = sess
	}
	return nil
}

func (m *memorySessions) Delete(_ context.Context, id SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func (m *memorySessions) DeletePerson(_ context.Context, person string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, sess := range m.sessions {
		if sess.Person == person {
			delete(m.sessions, k)
		}
	}
	return nil
}

func (m *memorySessions) Sweep(_ context.Context, now time.Time, idle time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, sess := range m.sessions {
		if !now.Before(sess.Expires) || now.Sub(sess.LastSeen) >= idle {
			delete(m.sessions, k)
		}
	}
	return nil
}

// count returns the number of pending, or complete, sessions. m.mu must be
// held.
func (m *memorySessions) count(pending bool) int {
	n := 0
	for _, sess := range m.sessions {
		if sess.Pending == pending {
			n++
		}
	}
	return n
}

// evictOldest removes the least recently used pending, or complete,
// session. m.mu must be held.
func (m *memorySessions) evictOldest(pending bool) {
	var (
		oldest SessionID
		seen   time.Time
		found  bool
	)
	for k, sess := range m.sessions {
		if sess.Pending == pending && (!found || sess.LastSeen.Before(seen)) {
			oldest, seen, found = k, sess.LastSeen, true
		}
	}
	if found {
		delete(m.sessions, oldest)
	}
}
