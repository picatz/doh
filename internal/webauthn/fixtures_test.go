package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/picatz/doh/internal/cose"
)

var updateFixtures = flag.Bool("update-fixtures", false, "regenerate testdata/software-fixtures.json")

// recordedFixture is one registration and one authentication produced by
// the deterministic software authenticator, kept so verification can be
// checked against fixed bytes across releases and against other relying
// parties. Keys are derived from fixed labels; ECDSA signatures are
// randomized, so regenerating changes the signature bytes.
type recordedFixture struct {
	Name                  string          `json:"name"`
	UserHandle            Base64URL       `json:"userHandle"`
	RegistrationChallenge Base64URL       `json:"registrationChallenge"`
	Registration          json.RawMessage `json:"registration"`
	LoginChallenge        Base64URL       `json:"authenticationChallenge"`
	Login                 json.RawMessage `json:"authentication"`
	AttestationRoot       Base64URL       `json:"attestationRoot,omitempty"`
}

type recordedFixtures struct {
	Note     string            `json:"note"`
	RPID     string            `json:"rpId"`
	Origin   string            `json:"origin"`
	Fixtures []recordedFixture `json:"fixtures"`
}

const fixturePath = "testdata/software-fixtures.json"

func generateFixtures(t *testing.T) recordedFixtures {
	out := recordedFixtures{Note: "Synthetic responses from the relyingparty test software authenticator. Not browser or hardware output.", RPID: testRPID, Origin: testOrigin}
	for _, c := range []struct {
		alg    cose.Algorithm
		format string
	}{{cose.AlgorithmES256, "none"}, {cose.AlgorithmES256, "packed-self"}, {cose.AlgorithmES256, "packed"}, {cose.AlgorithmES256, "fido-u2f"}, {cose.AlgorithmEdDSA, "none"}, {cose.AlgorithmEdDSA, "packed-self"}} {
		a := newSoft(t, c.alg, c.format)
		name := c.alg.String() + "/" + c.format
		regChallenge := sha256.Sum256([]byte("registration " + name))
		loginChallenge := sha256.Sum256([]byte("authentication " + name))
		reg := a.register(t, &RegistrationOptions{Options: CredentialCreationOptions{PublicKey: CreationOptions{RP: RelyingPartyEntity{ID: testRPID}, User: UserEntity{ID: testUser}, Challenge: regChallenge[:]}}}, testOrigin, tweak{})
		login := a.login(t, &LoginOptions{Options: CredentialRequestOptions{PublicKey: RequestOptions{RPID: testRPID, Challenge: loginChallenge[:]}}}, testOrigin, tweak{})
		f := recordedFixture{Name: name, UserHandle: testUser, RegistrationChallenge: regChallenge[:], Registration: reg, LoginChallenge: loginChallenge[:], Login: login}
		if a.attestation != nil {
			f.AttestationRoot = rootDER(t, a)
		}
		out.Fixtures = append(out.Fixtures, f)
	}
	return out
}

// rootDER regenerates the CA certificate's DER for the fixture file.
func rootDER(t *testing.T, a *softAuthenticator) []byte {
	leaf, err := x509.ParseCertificate(a.attestation.chain[0])
	if err != nil {
		t.Fatal(err)
	}
	// The pool holds exactly the issuing CA; find it by verifying the leaf.
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: a.attestation.root, CurrentTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		t.Fatal(err)
	}
	return chains[0][len(chains[0])-1].Raw
}

// TestRecordedFixtures verifies the committed software-authenticator
// fixtures. Run with -update-fixtures to regenerate them.
func TestRecordedFixtures(t *testing.T) {
	if *updateFixtures {
		data, err := json.MarshalIndent(generateFixtures(t), "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.FromSlash(fixturePath), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.FromSlash(fixturePath))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures recordedFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Fixtures) != 6 {
		t.Fatalf("got %d fixtures", len(fixtures.Fixtures))
	}
	for _, f := range fixtures.Fixtures {
		t.Run(f.Name, func(t *testing.T) {
			rp, _ := newTestRP(t, func(c *Config) {
				c.ID, c.Origins = fixtures.RPID, []string{fixtures.Origin}
				if len(f.AttestationRoot) != 0 {
					root, err := x509.ParseCertificate(f.AttestationRoot)
					if err != nil {
						t.Fatal(err)
					}
					pool := x509.NewCertPool()
					pool.AddCert(root)
					c.Policy.TrustAttestation = func(_ context.Context, a Attestation) error {
						return verifyChain(pool, a, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
					}
				}
			})
			id := inject(t, rp, Ceremony{Kind: CeremonyRegistration, Challenge: f.RegistrationChallenge, UserHandle: f.UserHandle,
				UserVerification: UserVerificationRequired, Algorithms: defaultAlgorithms})
			registration, err := rp.FinishRegistration(context.Background(), id, testBinding, f.Registration)
			if err != nil {
				t.Fatalf("registration: %v", err)
			}
			id = inject(t, rp, Ceremony{Kind: CeremonyLogin, Challenge: f.LoginChallenge, UserVerification: UserVerificationRequired})
			login, err := rp.FinishLogin(context.Background(), id, testBinding, f.Login, lookupFor(registration.Credential))
			if err != nil {
				t.Fatalf("authentication: %v", err)
			}
			if !bytes.Equal(login.UserHandle, f.UserHandle) || login.Credential.SignCount != 1 {
				t.Fatalf("login = %+v", login)
			}
		})
	}
}
