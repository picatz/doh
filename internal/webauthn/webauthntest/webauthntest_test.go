package webauthntest

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/picatz/doh/internal/webauthn"
)

func TestAuthenticator(t *testing.T) {
	store, err := webauthn.NewMemoryChallengeStore(16)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := webauthn.New(webauthn.Config{ID: "localhost", Origins: []string{"http://localhost:9090"}, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	const binding = "test-session-binding-0123456789"
	user := []byte("user-handle-1")
	origin := Response{Origin: "http://localhost:9090"}

	var a Authenticator
	reg, err := rp.BeginRegistration(t.Context(), webauthn.RegistrationRequest{Binding: binding, User: webauthn.UserEntity{ID: user, Name: "admin", DisplayName: "Admin"}})
	if err != nil {
		t.Fatal(err)
	}
	created, err := a.Create(reg.Options.PublicKey, origin)
	if err != nil {
		t.Fatal(err)
	}
	registration, err := rp.FinishRegistration(t.Context(), reg.ID, binding, created)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}

	for i := range 2 {
		login, err := rp.BeginLogin(t.Context(), webauthn.LoginRequest{Binding: binding})
		if err != nil {
			t.Fatal(err)
		}
		assertion, err := a.Get(login.Options.PublicKey, origin)
		if err != nil {
			t.Fatal(err)
		}
		cred := registration.Credential
		got, err := rp.FinishLogin(t.Context(), login.ID, binding, assertion, func(_ context.Context, id, handle []byte) (*webauthn.Credential, error) {
			return &cred, nil
		})
		if err != nil {
			t.Fatalf("FinishLogin %d: %v", i, err)
		}
		if !bytes.Equal(got.UserHandle, user) {
			t.Errorf("user handle %q", got.UserHandle)
		}
		registration.Credential = got.Credential
	}

	// A forged signature fails.
	login, _ := rp.BeginLogin(t.Context(), webauthn.LoginRequest{Binding: binding})
	assertion, _ := a.Get(login.Options.PublicKey, Response{Origin: origin.Origin, Signature: func(b []byte) []byte { b[len(b)-1] ^= 1; return b }})
	cred := registration.Credential
	if _, err := rp.FinishLogin(t.Context(), login.ID, binding, assertion, func(_ context.Context, id, handle []byte) (*webauthn.Credential, error) { return &cred, nil }); !errors.Is(err, webauthn.ErrVerification) {
		t.Errorf("forged signature: %v, want a verification error", err)
	}

	if _, err := a.Get(webauthn.RequestOptions{RPID: "other.example"}, origin); !errors.Is(err, ErrNoCredential) {
		t.Errorf("other RP: %v", err)
	}
}
