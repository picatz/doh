package signin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/picatz/doh/internal/webauthn"
)

// Prefix is the path prefix of the sign-in endpoints [Service.Handler]
// serves:
//
//	GET  /auth/session                    SessionStatus
//	POST /auth/link                       {"code"} → SessionStatus
//	POST /auth/passkey/login              → webauthn.LoginOptions
//	POST /auth/passkey/login/{ceremony}   AuthenticationResponseJSON → SessionStatus
//	POST /auth/passkey/register           {"name", "person"} → webauthn.RegistrationOptions
//	POST /auth/passkey/register/{ceremony} RegistrationResponseJSON → Passkey
//	POST /auth/signout                    204
//
// Every POST must come from the UI's own origin: cross-origin requests are
// refused, which together with SameSite=Strict cookies protects against
// cross-site request forgery.
const Prefix = "/auth"

// maxBody bounds sign-in request bodies other than WebAuthn responses,
// which the relying party bounds itself.
const maxBody = 4 << 10

// SessionStatus is what the UI needs to know about its session.
type SessionStatus struct {
	// SignedIn reports a complete session.
	SignedIn bool `json:"signed_in"`

	// Session is the session, if there is one, complete or pending.
	Session *Session `json:"session,omitempty"`

	// PasskeysRequired reports that link sign-ins must be completed with a
	// passkey, because someone has one.
	PasskeysRequired bool `json:"passkeys_required"`

	// RPID is the host passkeys are created for. Passkeys only work when
	// the UI is opened at an origin on this host.
	RPID string `json:"rp_id"`
}

// Handler returns the sign-in endpoints, under [Prefix].
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Prefix+"/session", s.handleSession)
	mux.HandleFunc("POST "+Prefix+"/link", s.handleLink)
	mux.HandleFunc("POST "+Prefix+"/passkey/login", s.handleLoginBegin)
	mux.HandleFunc("POST "+Prefix+"/passkey/login/{ceremony}", s.handleLoginFinish)
	mux.HandleFunc("POST "+Prefix+"/passkey/register", s.handleRegisterBegin)
	mux.HandleFunc("POST "+Prefix+"/passkey/register/{ceremony}", s.handleRegisterFinish)
	mux.HandleFunc("POST "+Prefix+"/signout", s.handleSignOut)

	return http.NewCrossOriginProtection().Handler(noStore(mux))
}

// noStore keeps responses out of caches: they carry session state.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Service) status(sess Session, ok bool) SessionStatus {
	st := SessionStatus{PasskeysRequired: s.HasPasskeys(), RPID: s.rpID}
	if ok {
		st.Session = &sess
		st.SignedIn = !sess.Pending
	}
	return st
}

func (s *Service) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.Session(r)
	writeJSON(w, http.StatusOK, s.status(sess, ok))
}

// handleLink exchanges a sign-in link's code for a session: a complete
// one if no one has a passkey yet, otherwise a pending one that a passkey
// must complete.
func (s *Service) handleLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}

	l, ok := s.consumeLink(req.Code)
	if !ok {
		writeError(w, http.StatusUnauthorized, "this sign-in link is invalid, used, or expired; run doh ui for a new one")
		return
	}

	pending := s.HasPasskeys()
	sess := Session{Name: "Sign-in link", Role: l.role, Method: "link", Pending: pending}
	if err := s.startSession(w, r, sess); err != nil {
		writeError(w, http.StatusInternalServerError, "starting a session failed")
		return
	}
	s.logger.InfoContext(r.Context(), "signin: link used", slog.String("role", string(l.role)), slog.Bool("passkey_required", pending))

	sess, ok = s.Session(r)
	writeJSON(w, http.StatusOK, s.status(sess, ok))
}

// consumeLink takes a link's code, so it can only be used once.
func (s *Service) consumeLink(code string) (link, bool) {
	if code == "" || len(code) > 128 {
		return link{}, false
	}
	key := sha256.Sum256([]byte(code))

	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.links[key]
	delete(s.links, key)
	if !ok || !s.now().Before(l.expires) {
		return link{}, false
	}
	return l, true
}

// handleLoginBegin starts a passkey sign-in. Without a session, it starts a
// pending one first, whose cookie binds the ceremony to this browser.
func (s *Service) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.Session(r); !ok {
		if err := s.startSession(w, r, Session{Name: "Signing in", Method: "none", Pending: true}); err != nil {
			writeError(w, http.StatusInternalServerError, "starting a session failed")
			return
		}
	}
	binding, _ := s.binding(r)

	options, err := s.rp.BeginLogin(r.Context(), webauthn.LoginRequest{Binding: binding})
	if err != nil {
		s.logger.ErrorContext(r.Context(), "signin: beginning passkey sign-in", slog.Any("error", err))
		writeError(w, http.StatusServiceUnavailable, "passkey sign-in is unavailable; try again shortly")
		return
	}
	writeJSON(w, http.StatusOK, options)
}

// handleLoginFinish verifies a passkey sign-in and completes the session,
// under a new ID.
func (s *Service) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	prior, ok := s.Session(r)
	binding, hasBinding := s.binding(r)
	if !ok || !hasBinding {
		writeError(w, http.StatusUnauthorized, "start the passkey sign-in again")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "response too large")
		return
	}

	login, err := s.rp.FinishLogin(r.Context(), r.PathValue("ceremony"), binding, body, s.lookup)
	if err != nil {
		s.logger.WarnContext(r.Context(), "signin: passkey sign-in failed", slog.Any("error", err))
		writeError(w, http.StatusUnauthorized, "that passkey couldn't sign you in")
		return
	}

	person, err := s.recordLogin(login)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "signin: recording passkey use", slog.Any("error", err))
		writeError(w, http.StatusUnauthorized, "that passkey couldn't sign you in")
		return
	}

	method := "passkey"
	if prior.Method == "link" {
		method = "link+passkey"
	}
	sess := Session{Person: person.ID, Name: person.Name, Role: person.Role, Method: method}
	if err := s.startSession(w, r, sess); err != nil {
		writeError(w, http.StatusInternalServerError, "starting a session failed")
		return
	}
	s.logger.InfoContext(r.Context(), "signin: signed in", slog.String("person", person.ID), slog.String("method", method))

	sess, ok = s.Session(r)
	writeJSON(w, http.StatusOK, s.status(sess, ok))
}

// lookup finds the credential record a passkey sign-in asserted.
func (s *Service) lookup(_ context.Context, credentialID, userHandle []byte) (*webauthn.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.people {
		for _, k := range p.Passkeys {
			if string(k.Credential.ID) == string(credentialID) {
				c := k.Credential
				return &c, nil
			}
		}
	}
	return nil, webauthn.ErrCredential
}

// recordLogin persists a passkey's updated record after a sign-in,
// failing if its counter moved since the sign-in read it, so concurrent
// sign-ins can't roll it back.
func (s *Service) recordLogin(login *webauthn.Login) (Person, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	people := slices.Clone(s.people)
	for i := range people {
		p := &people[i]
		for j := range p.Passkeys {
			k := &p.Passkeys[j]
			if string(k.Credential.ID) != string(login.Credential.ID) {
				continue
			}
			if k.Credential.SignCount != login.PreviousSignCount {
				return Person{}, errors.New("signin: passkey used concurrently")
			}
			p.Passkeys = slices.Clone(p.Passkeys)
			k = &p.Passkeys[j]
			k.Credential = login.Credential
			k.LastUsed = s.now()
			k.Synced = login.Credential.BackupState
			if err := s.save(people); err != nil {
				return Person{}, err
			}
			s.people = people
			return *p, nil
		}
	}
	return Person{}, webauthn.ErrCredential
}

// handleRegisterBegin starts adding a passkey: to the signed-in person, or
// for a link session, to a new person with the link's role.
func (s *Service) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.Session(r)
	if !ok || sess.Pending {
		writeError(w, http.StatusUnauthorized, "sign in to add a passkey")
		return
	}

	var req struct {
		Name   string `json:"name"`
		Person string `json:"person"`
	}
	if !decode(w, r, &req) {
		return
	}
	passkeyName, ok := validName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "name the passkey with 1 to 64 characters, such as \"MacBook\"")
		return
	}

	handle, personName, exclude, err := s.enrollee(sess, req.Person)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	binding, _ := s.binding(r)
	options, err := s.rp.BeginRegistration(r.Context(), webauthn.RegistrationRequest{
		Binding:            binding,
		User:               webauthn.UserEntity{ID: handle, Name: personName, DisplayName: personName},
		ExcludeCredentials: exclude,
		ResidentKey:        webauthn.ResidentKeyRequired,
	})
	if err != nil {
		s.logger.ErrorContext(r.Context(), "signin: beginning passkey registration", slog.Any("error", err))
		writeError(w, http.StatusServiceUnavailable, "adding passkeys is unavailable; try again shortly")
		return
	}

	s.mu.Lock()
	now := s.now()
	for id, e := range s.enrollments {
		if !now.Before(e.expires) {
			delete(s.enrollments, id)
		}
	}
	if len(s.enrollments) >= maxEnrollments {
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "too many passkeys are being added at once; try again shortly")
		return
	}
	s.enrollments[options.ID] = enrollment{handle: handle, person: personName, passkey: passkeyName, role: sess.Role, expires: now.Add(pendingLifetime)}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, options)
}

// enrollment is a pending passkey registration: what the relying party's
// ceremony doesn't carry.
type enrollment struct {
	handle  []byte
	person  string
	passkey string
	role    Role
	expires time.Time
}

// maxEnrollments bounds pending passkey registrations.
const maxEnrollments = 100

// enrollee returns who a session's new passkey is for: the signed-in
// person, or for a link session, a new person named name.
func (s *Service) enrollee(sess Session, name string) (handle []byte, person string, exclude []webauthn.CredentialDescriptor, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess.Person != "" {
		i := slices.IndexFunc(s.people, func(p Person) bool { return p.ID == sess.Person })
		if i < 0 {
			return nil, "", nil, errors.New("your account was removed; sign in again")
		}
		p := s.people[i]
		if len(p.Passkeys) >= maxPasskeys {
			return nil, "", nil, errors.New("you have the most passkeys allowed; remove one first")
		}
		for _, k := range p.Passkeys {
			exclude = append(exclude, webauthn.CredentialDescriptor{Type: "public-key", ID: k.Credential.ID, Transports: k.Credential.Transports})
		}
		handle, _ = base64.RawURLEncoding.DecodeString(p.ID)
		return handle, p.Name, exclude, nil
	}

	person, ok := validName(name)
	if !ok {
		return nil, "", nil, errors.New("name yourself with 1 to 64 characters, so others know whose passkey this is")
	}
	if len(s.people) >= maxPeople {
		return nil, "", nil, errors.New("there are as many people as allowed; remove someone first")
	}
	handle = make([]byte, 16)
	if _, err := rand.Read(handle); err != nil {
		return nil, "", nil, err
	}
	return handle, person, nil, nil
}

// handleRegisterFinish verifies a new passkey and stores it.
func (s *Service) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.Session(r)
	binding, hasBinding := s.binding(r)
	if !ok || sess.Pending || !hasBinding {
		writeError(w, http.StatusUnauthorized, "sign in to add a passkey")
		return
	}

	ceremony := r.PathValue("ceremony")
	s.mu.Lock()
	e, found := s.enrollments[ceremony]
	delete(s.enrollments, ceremony)
	found = found && s.now().Before(e.expires)
	s.mu.Unlock()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "response too large")
		return
	}

	// Finish even if the enrollment is unknown, so the ceremony is
	// consumed; then refuse.
	reg, err := s.rp.FinishRegistration(r.Context(), ceremony, binding, body)
	if err != nil || !found {
		s.logger.WarnContext(r.Context(), "signin: passkey registration failed", slog.Any("error", err))
		writeError(w, http.StatusBadRequest, "that passkey couldn't be added; try again")
		return
	}

	passkey, person, err := s.addPasskey(e, reg.Credential)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	// A link session becomes the new person's session, under a new ID.
	if sess.Person == "" {
		next := Session{Person: person.ID, Name: person.Name, Role: person.Role, Method: sess.Method}
		if err := s.startSession(w, r, next); err != nil {
			writeError(w, http.StatusInternalServerError, "starting a session failed")
			return
		}
	}
	s.logger.InfoContext(r.Context(), "signin: passkey added", slog.String("person", person.ID), slog.String("passkey", passkey.Name))

	passkey.Credential = webauthn.Credential{}
	writeJSON(w, http.StatusCreated, passkey)
}

// addPasskey stores a verified credential for an enrollment, creating its
// person if they're new.
func (s *Service) addPasskey(e enrollment, cred webauthn.Credential) (Passkey, Person, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.people {
		for _, k := range p.Passkeys {
			if string(k.Credential.ID) == string(cred.ID) {
				return Passkey{}, Person{}, errors.New("that passkey is already added")
			}
		}
	}

	now := s.now()
	passkey := Passkey{
		ID:         base64.RawURLEncoding.EncodeToString(cred.ID),
		Name:       e.passkey,
		Created:    now,
		Synced:     cred.BackupState,
		Credential: cred,
	}

	id := base64.RawURLEncoding.EncodeToString(e.handle)
	people := slices.Clone(s.people)
	i := slices.IndexFunc(people, func(p Person) bool { return p.ID == id })
	if i < 0 {
		people = append(people, Person{ID: id, Name: e.person, Role: e.role, Created: now})
		i = len(people) - 1
	}
	people[i].Passkeys = append(slices.Clone(people[i].Passkeys), passkey)

	if err := s.save(people); err != nil {
		return Passkey{}, Person{}, err
	}
	s.people = people
	return passkey, people[i], nil
}

func (s *Service) handleSignOut(w http.ResponseWriter, r *http.Request) {
	s.endSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// decode reads a small JSON request body into v, writing any error.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return false
	}
	if err := json.Unmarshal(b, v, json.RejectUnknownMembers(true)); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{msg})
}
