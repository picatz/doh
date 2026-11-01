package webauthn

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/cose"
)

// TestLoginIsNoCredentialOracle checks that FinishLogin consults the
// credential lookup only after the challenge, origin, rpIdHash and flags
// verify, and that an unknown credential and a bad signature then fail
// identically.
func TestLoginIsNoCredentialOracle(t *testing.T) {
	ctx := context.Background()
	rp, _ := newTestRP(t, nil)
	a := newSoft(t, cose.AlgorithmES256, "none")
	options := beginRegistration(t, rp, testUser)
	registration, err := rp.FinishRegistration(ctx, options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
	if err != nil {
		t.Fatal(err)
	}
	for name, tw := range map[string]tweak{
		"challenge": {clientData: func(m map[string]any) { m["challenge"] = b64(make([]byte, 32)) }},
		"origin":    {clientData: func(m map[string]any) { m["origin"] = "https://evil.example" }},
		"type":      {clientData: func(m map[string]any) { m["type"] = "webauthn.create" }},
		"rp-id":     {rpID: "evil.example"},
		"presence":  {authData: flipFlags(0, FlagUserPresent)},
		"uv":        {authData: flipFlags(0, FlagUserVerified)},
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			lookup := func(context.Context, []byte, []byte) (*Credential, error) { called = true; return nil, ErrCredential }
			login := beginLogin(t, rp, testUser)
			if _, err := rp.FinishLogin(ctx, login.ID, testBinding, a.login(t, login, testOrigin, tw), lookup); err == nil {
				t.Fatal("FinishLogin succeeded")
			}
			if called {
				t.Fatal("credential lookup ran before the response was bound to the ceremony")
			}
		})
	}

	finish := func(tw tweak, lookup CredentialLookup) *VerificationError {
		t.Helper()
		login := beginLogin(t, rp, testUser)
		_, err := rp.FinishLogin(ctx, login.ID, testBinding, a.login(t, login, testOrigin, tw), lookup)
		var verr *VerificationError
		if !errors.As(err, &verr) {
			t.Fatalf("error = %v, want a VerificationError", err)
		}
		return verr
	}
	badSignature := tweak{signature: func(s []byte) []byte { s[len(s)-1] ^= 1; return s }}
	other := registration.Credential.Clone()
	other.UserHandle = []byte("someone else")
	results := map[string]*VerificationError{
		"unknown credential": finish(tweak{}, lookupFor()),
		"nil record":         finish(tweak{}, func(context.Context, []byte, []byte) (*Credential, error) { return nil, nil }),
		"other account":      finish(tweak{}, lookupFor(other)),
		"bad signature":      finish(badSignature, lookupFor(registration.Credential)),
	}
	want := results["bad signature"]
	details := map[string]bool{}
	for name, got := range results {
		if got.Error() != want.Error() || errors.Is(got, ErrCredential) || !errors.Is(got, ErrVerification) || got.Step != stepAssertion {
			t.Errorf("%s: %q (credential sentinel %v), want %q", name, got, errors.Is(got, ErrCredential), want)
		}
		if got.Detail == "" || strings.Contains(got.Error(), got.Detail) {
			t.Errorf("%s: Detail %q must be set and kept out of the message", name, got.Detail)
		}
		details[got.Detail] = true
	}
	if len(details) < 3 {
		t.Errorf("operators cannot tell the failures apart: %v", details)
	}
	// A lookup failure that is not ErrCredential (an outage) is passed on.
	outage := errors.New("database unavailable")
	login := beginLogin(t, rp, testUser)
	if _, err := rp.FinishLogin(ctx, login.ID, testBinding, a.login(t, login, testOrigin, tweak{}),
		func(context.Context, []byte, []byte) (*Credential, error) { return nil, outage }); !errors.Is(err, outage) {
		t.Fatalf("outage error = %v", err)
	}
}

// TestCredentialIDBoundInJSON checks that a rawId over 1023 bytes is
// rejected while parsing, before any lookup sees it.
func TestCredentialIDBoundInJSON(t *testing.T) {
	response := func(n int) []byte {
		id := b64(bytes.Repeat([]byte{1}, n))
		return []byte(`{"id":"` + id + `","rawId":"` + id + `","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AA"}}`)
	}
	if _, err := ParseAuthenticationResponse(response(maxCredentialID)); err != nil {
		t.Fatalf("1023-byte rawId: %v", err)
	}
	if _, err := ParseAuthenticationResponse(response(maxCredentialID + 1)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("1024-byte rawId: %v, want ErrMalformed", err)
	}
	rp, _ := newTestRP(t, nil)
	login := beginLogin(t, rp, testUser)
	lookup := func(context.Context, []byte, []byte) (*Credential, error) {
		t.Error("lookup called")
		return nil, ErrCredential
	}
	if _, err := rp.FinishLogin(context.Background(), login.ID, testBinding, response(maxCredentialID+1), lookup); !errors.Is(err, ErrMalformed) {
		t.Fatalf("FinishLogin: %v, want ErrMalformed", err)
	}
}

// TestTrustRootsUsesRelyingPartyClock checks that TrustRoots validates the
// chain at Config.Clock's time during registration, and at time.Now
// otherwise.
func TestTrustRootsUsesRelyingPartyClock(t *testing.T) {
	a := newSoft(t, cose.AlgorithmES256, "packed")
	for _, tc := range []struct {
		at      time.Time
		trusted bool
	}{
		{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{time.Date(2125, 1, 1, 0, 0, 0, 0, time.UTC), false}, // after the leaf's NotAfter
		{time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC), false}, // before its NotBefore
	} {
		clock := &testClock{now: tc.at}
		rp, _ := newTestRP(t, func(c *Config) { c.Clock = clock.Now; c.Policy.TrustAttestation = TrustRoots(a.attestation.root) })
		options := beginRegistration(t, rp, testUser)
		_, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
		if tc.trusted && err != nil {
			t.Errorf("at %v: %v", tc.at, err)
		}
		if !tc.trusted {
			expectStep(t, err, ErrVerification, "not trusted")
		}
	}
	// Outside a ceremony the check runs at the current time.
	rp, _ := newTestRP(t, nil)
	options := beginRegistration(t, rp, testUser)
	registration, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := TrustRoots(a.attestation.root)(context.Background(), registration.Attestation); err != nil {
		t.Fatalf("TrustRoots at time.Now: %v", err)
	}
}

// TestMemoryStoreEvictsByItsClock checks that a full MemoryChallengeStore
// discards expired ceremonies by its Now clock, the clock the relying party
// hands Consume, rather than by time.Now.
func TestMemoryStoreEvictsByItsClock(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)} // long before time.Now
	store, err := NewMemoryChallengeStore(1)
	if err != nil {
		t.Fatal(err)
	}
	store.Now = clock.Now
	ceremony := Ceremony{Kind: CeremonyLogin, Challenge: make([]byte, 32), Expires: clock.now.Add(time.Minute)}
	if err := store.Put(ctx, CeremonyKey{Tenant: "t", ID: "a"}, ceremony); err != nil {
		t.Fatal(err)
	}
	// Unexpired by the store's clock, though long expired by time.Now: kept.
	if err := store.Put(ctx, CeremonyKey{Tenant: "t", ID: "b"}, ceremony); !errors.Is(err, ErrCapacity) {
		t.Fatalf("Put while full: %v, want ErrCapacity", err)
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if err := store.Put(ctx, CeremonyKey{Tenant: "t", ID: "b"}, ceremony); err != nil {
		t.Fatalf("Put after expiry by the store clock: %v", err)
	}
}

// TestCeremonyBoundToConfiguration checks that relying parties sharing a
// Store and Tenant but differing in verification settings cannot finish
// each other's ceremonies, while identically configured ones can.
func TestCeremonyBoundToConfiguration(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryChallengeStore(100)
	if err != nil {
		t.Fatal(err)
	}
	newRP := func(edit func(*Config)) *RelyingParty {
		config := Config{ID: testRPID, Store: store, Tenant: "shared"}
		if edit != nil {
			edit(&config)
		}
		rp, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		return rp
	}
	strict := newRP(nil)
	a := newSoft(t, cose.AlgorithmES256, "none")
	for name, other := range map[string]*RelyingParty{
		"user verification": newRP(func(c *Config) { c.Policy.UserVerification = UserVerificationDiscouraged }),
		"origins":           newRP(func(c *Config) { c.Origins = []string{testOrigin, "https://other.login.example.com"} }),
		"top origins":       newRP(func(c *Config) { c.TopOrigins = []string{"https://embedder.example"} }),
	} {
		options := beginRegistration(t, strict, testUser)
		if _, err := other.FinishRegistration(ctx, options.ID, testBinding, a.register(t, options, testOrigin, tweak{})); !errors.Is(err, ErrChallenge) {
			t.Errorf("%s differs: %v, want ErrChallenge", name, err)
		}
	}
	options := beginRegistration(t, strict, testUser)
	if _, err := newRP(nil).FinishRegistration(ctx, options.ID, testBinding, a.register(t, options, testOrigin, tweak{})); err != nil {
		t.Fatalf("identically configured relying party: %v", err)
	}
}

// TestRegistrationAttestationResult checks that a fido-u2f attestation does
// not vouch for the unsigned AAGUID and that returned certificates do not
// alias the stored attestation object.
func TestRegistrationAttestationResult(t *testing.T) {
	a := newSoft(t, cose.AlgorithmES256, "fido-u2f")
	rp, _ := newTestRP(t, nil)
	options := beginRegistration(t, rp, testUser)
	registration, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
	if err != nil {
		t.Fatal(err)
	}
	if !registration.Attestation.AAGUID.IsZero() || registration.Credential.AAGUID != a.aaguid {
		t.Fatalf("attestation AAGUID = %v, credential AAGUID = %v", registration.Attestation.AAGUID, registration.Credential.AAGUID)
	}
	object := bytes.Clone(registration.Credential.AttestationObject)
	for _, certificate := range registration.Attestation.Certificates {
		clear(certificate)
	}
	if !bytes.Equal(object, registration.Credential.AttestationObject) {
		t.Fatal("attestation certificates alias the attestation object")
	}
}
