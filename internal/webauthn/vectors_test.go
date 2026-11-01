package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/picatz/doh/internal/cose"
)

// w3cVectors is testdata/w3c-test-vectors.json, extracted from the Test
// Vectors appendix of the WebAuthn specification source.
type w3cVectors struct {
	RPID              string `json:"rpId"`
	Origin            string `json:"origin"`
	TopOrigin         string `json:"topOrigin"`
	AttestationCACert string `json:"attestation_ca_cert"`
	Vectors           []struct {
		Name         string            `json:"name"`
		Registration map[string]string `json:"registration"`
		Login        map[string]string `json:"authentication"`
	} `json:"vectors"`
}

func loadVectors(t testing.TB) w3cVectors {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "w3c-test-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v w3cVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// inject stores a ceremony with a known challenge, as BeginRegistration or
// BeginLogin would have, and returns its ID.
func inject(t testing.TB, rp *RelyingParty, ceremony Ceremony) string {
	t.Helper()
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	ceremony.RPID = rp.id
	ceremony.ConfigHash = rp.configHash
	if ceremony.Expires.IsZero() {
		ceremony.Expires = rp.now().Add(time.Minute)
	}
	if err := rp.store.Put(context.Background(), rp.key(id, testBinding), ceremony); err != nil {
		t.Fatal(err)
	}
	return b64(id)
}

var allAlgorithms = []cose.Algorithm{cose.AlgorithmES256, cose.AlgorithmEdDSA, cose.AlgorithmES384, cose.AlgorithmES512, cose.AlgorithmRS256, cose.AlgorithmPS256}

// TestW3CTestVectors runs every registration and authentication example of
// the specification's test vectors through the ceremony verification.
func TestW3CTestVectors(t *testing.T) {
	v := loadVectors(t)
	roots := x509.NewCertPool()
	ca, err := x509.ParseCertificate(unhex(t, v.AttestationCACert))
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(ca)

	type outcome struct {
		register  error // nil means success
		topOrigin bool
		trusted   bool // the trust path chains to the test vector CA
	}
	expected := map[string]outcome{
		"none-es256":                    {},
		"packed-self-es256":             {},
		"none-es256-crossOrigin":        {register: ErrVerification}, // crossOrigin without topOrigin
		"none-es256-topOrigin":          {topOrigin: true},
		"none-es256-long-credential-id": {},
		"packed-es256":                  {trusted: true},
		"packed-es384":                  {trusted: true},
		"packed-es512":                  {trusted: true},
		"packed-rs256":                  {trusted: true},
		"packed-eddsa":                  {trusted: true},
		"packed-ed448":                  {register: ErrUnsupported},
		"tpm-es256":                     {register: ErrUnsupported},
		"android-key-es256":             {register: ErrUnsupported},
		"apple-es256":                   {register: ErrUnsupported},
		"fido-u2f-es256":                {trusted: true},
	}
	if len(v.Vectors) != len(expected) {
		t.Fatalf("got %d vectors, want %d; update the expectations", len(v.Vectors), len(expected))
	}
	for _, vector := range v.Vectors {
		want, ok := expected[vector.Name]
		if !ok {
			t.Fatalf("no expectation for vector %q", vector.Name)
		}
		t.Run(vector.Name, func(t *testing.T) {
			rp, _ := newTestRP(t, func(c *Config) {
				c.ID, c.Origins = v.RPID, []string{v.Origin}
				c.Policy.UserVerification = UserVerificationPreferred
				c.Policy.Algorithms = allAlgorithms
				if want.topOrigin {
					c.TopOrigins = []string{v.TopOrigin}
				}
			})
			user := []byte("vector user")
			reg := vector.Registration
			credentialID := unhex(t, reg["credential_id"])
			response, _ := json.Marshal(map[string]any{
				"id": b64(credentialID), "rawId": b64(credentialID), "type": "public-key", "clientExtensionResults": map[string]any{},
				"response": map[string]any{"clientDataJSON": b64(unhex(t, reg["clientDataJSON"])), "attestationObject": b64(unhex(t, reg["attestationObject"]))},
			})
			id := inject(t, rp, Ceremony{Kind: CeremonyRegistration, Challenge: unhex(t, reg["challenge"]), UserHandle: user,
				UserVerification: UserVerificationPreferred, Algorithms: allAlgorithms})
			registration, err := rp.FinishRegistration(context.Background(), id, testBinding, response)
			if want.register != nil {
				if !errors.Is(err, want.register) {
					t.Fatalf("FinishRegistration error = %v, want %v", err, want.register)
				}
				return
			}
			if err != nil {
				t.Fatalf("FinishRegistration: %v", err)
			}
			if got := registration.Credential.AAGUID; hexAAGUID(got) != reg["aaguid"] {
				t.Errorf("AAGUID = %s, want %s", got, reg["aaguid"])
			}
			trustErr := verifyChain(roots, registration.Attestation, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			if want.trusted != (trustErr == nil) {
				t.Errorf("trust path chains to the vector CA = %v, want %v (%v)", trustErr == nil, want.trusted, trustErr)
			}

			login := vector.Login
			id = inject(t, rp, Ceremony{Kind: CeremonyLogin, Challenge: unhex(t, login["challenge"]), UserHandle: user, UserVerification: UserVerificationPreferred})
			assertion, _ := json.Marshal(map[string]any{
				"id": b64(credentialID), "rawId": b64(credentialID), "type": "public-key", "clientExtensionResults": map[string]any{},
				"response": map[string]any{"clientDataJSON": b64(unhex(t, login["clientDataJSON"])), "authenticatorData": b64(unhex(t, login["authenticatorData"])), "signature": b64(unhex(t, login["signature"]))},
			})
			result, err := rp.FinishLogin(context.Background(), id, testBinding, assertion, lookupFor(registration.Credential))
			if err != nil {
				t.Fatalf("FinishLogin: %v", err)
			}
			if string(result.UserHandle) != string(user) {
				t.Errorf("UserHandle = %q", result.UserHandle)
			}

			// The same assertion against a changed signature must fail.
			id = inject(t, rp, Ceremony{Kind: CeremonyLogin, Challenge: unhex(t, login["challenge"]), UserHandle: user, UserVerification: UserVerificationPreferred})
			bad := unhex(t, login["signature"])
			bad[len(bad)-1] ^= 1
			tampered, _ := json.Marshal(map[string]any{
				"id": b64(credentialID), "rawId": b64(credentialID), "type": "public-key", "clientExtensionResults": map[string]any{},
				"response": map[string]any{"clientDataJSON": b64(unhex(t, login["clientDataJSON"])), "authenticatorData": b64(unhex(t, login["authenticatorData"])), "signature": b64(bad)},
			})
			if _, err := rp.FinishLogin(context.Background(), id, testBinding, tampered, lookupFor(registration.Credential)); !errors.Is(err, ErrVerification) {
				t.Fatalf("tampered signature: %v", err)
			}
		})
	}
}

func hexAAGUID(a AAGUID) string { return hex.EncodeToString(a[:]) }

// TestW3CTopOriginRequiresConfiguration checks that the topOrigin vector is
// rejected unless the relying party lists the embedding page.
func TestW3CTopOriginRequiresConfiguration(t *testing.T) {
	v := loadVectors(t)
	for _, vector := range v.Vectors {
		if vector.Name != "none-es256-topOrigin" {
			continue
		}
		for _, top := range [][]string{nil, {"https://other.example"}} {
			rp, _ := newTestRP(t, func(c *Config) {
				c.ID, c.Origins, c.TopOrigins = v.RPID, []string{v.Origin}, top
				c.Policy.UserVerification = UserVerificationPreferred
			})
			reg := vector.Registration
			credentialID := unhex(t, reg["credential_id"])
			response, _ := json.Marshal(map[string]any{
				"id": b64(credentialID), "rawId": b64(credentialID), "type": "public-key", "clientExtensionResults": map[string]any{},
				"response": map[string]any{"clientDataJSON": b64(unhex(t, reg["clientDataJSON"])), "attestationObject": b64(unhex(t, reg["attestationObject"]))},
			})
			id := inject(t, rp, Ceremony{Kind: CeremonyRegistration, Challenge: unhex(t, reg["challenge"]), UserHandle: []byte("u"),
				UserVerification: UserVerificationPreferred, Algorithms: defaultAlgorithms})
			var verr *VerificationError
			if _, err := rp.FinishRegistration(context.Background(), id, testBinding, response); !errors.As(err, &verr) || !errors.Is(err, ErrVerification) {
				t.Fatalf("top origins %v: error = %v, want a VerificationError", top, err)
			}
		}
		return
	}
	t.Fatal("topOrigin vector missing")
}
