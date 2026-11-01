package webauthn_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/picatz/doh/internal/webauthn"
)

// Example shows the server side of both ceremonies. The HTTP handlers, the
// application's session and its credential table are the caller's; the
// comments mark where each belongs.
func Example() {
	store, err := webauthn.NewMemoryChallengeStore(10_000)
	if err != nil {
		log.Fatal(err)
	}
	rp, err := webauthn.New(webauthn.Config{
		ID:      "example.com",
		Name:    "Example",
		Origins: []string{"https://example.com"},
		Store:   store,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	// A random, server-side session identifier for the signed-in user.
	session := "6f1f0a4cbd0a4d2fa7e3c1d0"

	options, err := rp.BeginRegistration(ctx, webauthn.RegistrationRequest{
		Binding: session,
		User:    webauthn.UserEntity{ID: []byte("opaque-user-handle"), Name: "alice@example.com", DisplayName: "Alice"},
	})
	if err != nil {
		log.Fatal(err)
	}
	// Send options to the browser as JSON; it calls
	// navigator.credentials.create and posts back credential.toJSON().
	pk := options.Options.PublicKey
	fmt.Println(pk.RP.ID, pk.AuthenticatorSelection.UserVerification, pk.Attestation)
	var algorithms []string
	for _, p := range pk.PubKeyCredParams {
		algorithms = append(algorithms, p.Algorithm.String())
	}
	fmt.Println(strings.Join(algorithms, " "))

	// On the finish request, pass the posted body. This one is not a real
	// browser response, so verification fails; every attempt consumes the
	// ceremony.
	_, err = rp.FinishRegistration(ctx, options.ID, session, []byte(`{}`))
	fmt.Println(errors.Is(err, webauthn.ErrMalformed))
	_, err = rp.FinishRegistration(ctx, options.ID, session, []byte(`{}`))
	fmt.Println(errors.Is(err, webauthn.ErrChallenge))

	// Sign-in without a username: the authenticator returns the user handle,
	// and FinishLogin asks the lookup for the credential record.
	login, err := rp.BeginLogin(ctx, webauthn.LoginRequest{Binding: session, Mediation: webauthn.MediationConditional})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(login.Options.PublicKey.RPID, login.Options.Mediation)
	// Output:
	// example.com required none
	// ES256 EdDSA RS256
	// true
	// true
	// example.com conditional
}
