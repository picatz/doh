package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/picatz/doh/internal/cose"
)

var testUser = []byte("user-handle-0001")

// TestSoftwareRoundTrip registers and signs in with every software
// authenticator configuration, username-first and discoverable.
func TestSoftwareRoundTrip(t *testing.T) {
	cases := []struct {
		algorithm cose.Algorithm
		format    string
		attType   AttestationType
	}{
		{cose.AlgorithmES256, "none", AttestationTypeNone},
		{cose.AlgorithmES256, "packed-self", AttestationTypeSelf},
		{cose.AlgorithmES256, "packed", AttestationTypeBasic},
		{cose.AlgorithmES256, "fido-u2f", AttestationTypeBasic},
		{cose.AlgorithmEdDSA, "none", AttestationTypeNone},
		{cose.AlgorithmEdDSA, "packed-self", AttestationTypeSelf},
		{cose.AlgorithmEdDSA, "packed", AttestationTypeBasic},
	}
	for _, tc := range cases {
		t.Run(tc.algorithm.String()+"/"+tc.format, func(t *testing.T) {
			a := newSoft(t, tc.algorithm, tc.format)
			rp, store := newTestRP(t, func(c *Config) {
				if a.attestation != nil {
					c.Policy.TrustAttestation = TrustRoots(a.attestation.root)
				}
			})
			ctx := context.Background()
			options := beginRegistration(t, rp, testUser)
			registration, err := rp.FinishRegistration(ctx, options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
			if err != nil {
				t.Fatalf("FinishRegistration: %v", err)
			}
			c := registration.Credential
			if c.Algorithm != tc.algorithm || c.AttestationType != tc.attType || !bytes.Equal(c.ID, a.credentialID) || !bytes.Equal(c.UserHandle, testUser) ||
				c.RPID != testRPID || !c.UVInitialized || c.BackupEligible || c.AAGUID != a.aaguid || len(c.Transports) != 2 {
				t.Fatalf("unexpected credential record: %+v", c)
			}
			if registration.Extensions.CredProps == nil || registration.Extensions.CredProps.RK == nil || !*registration.Extensions.CredProps.RK {
				t.Errorf("credProps output not returned: %+v", registration.Extensions)
			}
			if store.Len() != 0 {
				t.Errorf("ceremony not consumed")
			}

			// Username-first login with allowCredentials.
			login := beginLogin(t, rp, testUser, c)
			result, err := rp.FinishLogin(ctx, login.ID, testBinding, a.login(t, login, testOrigin, tweak{}), lookupFor(c))
			if err != nil {
				t.Fatalf("FinishLogin: %v", err)
			}
			if result.Credential.SignCount != 1 || result.PreviousSignCount != 0 || result.CounterAnomaly || !result.UserVerified {
				t.Fatalf("unexpected login result: %+v", result)
			}
			c = result.Credential

			// Discoverable login: no user, no allowCredentials.
			login = beginLogin(t, rp, nil)
			result, err = rp.FinishLogin(ctx, login.ID, testBinding, a.login(t, login, testOrigin, tweak{}), lookupFor(c))
			if err != nil {
				t.Fatalf("discoverable FinishLogin: %v", err)
			}
			if !bytes.Equal(result.UserHandle, testUser) || result.Credential.SignCount != 2 {
				t.Fatalf("unexpected discoverable result: %+v", result)
			}

			// Replaying the same response fails: the ceremony is gone.
			replay := a.login(t, login, testOrigin, tweak{})
			if _, err := rp.FinishLogin(ctx, login.ID, testBinding, replay, lookupFor(result.Credential)); !errors.Is(err, ErrChallenge) {
				t.Fatalf("replay: %v, want ErrChallenge", err)
			}
		})
	}
}

// expectStep asserts err is a VerificationError wrapping sentinel whose step
// mentions fragment.
func expectStep(t *testing.T, err error, sentinel error, fragment string) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want %v", err, sentinel)
	}
	var verr *VerificationError
	if fragment != "" && (!errors.As(err, &verr) || !strings.Contains(verr.Step, fragment)) {
		t.Fatalf("error = %v, want a VerificationError step containing %q", err, fragment)
	}
	if verr != nil && !strings.HasPrefix(verr.Spec, "https://www.w3.org/TR/webauthn-3/#") {
		t.Fatalf("step %q links no specification section", verr.Step)
	}
}

func flipFlags(set, clear Flags) func([]byte) []byte {
	return func(data []byte) []byte {
		data[32] = byte((Flags(data[32]) | set) &^ clear)
		return data
	}
}

// TestRegistrationRejects covers a negative case for every registration
// verification step.
func TestRegistrationRejects(t *testing.T) {
	otherCA := newTestAttestationCA(t, "another CA", AAGUID{}, nil)
	cases := []struct {
		name     string
		format   string
		alg      cose.Algorithm
		config   func(*Config)
		tweak    tweak
		sentinel error
		step     string
	}{
		{name: "type", tweak: tweak{clientData: func(m map[string]any) { m["type"] = "webauthn.get" }}, sentinel: ErrVerification, step: "type"},
		{name: "challenge", tweak: tweak{clientData: func(m map[string]any) { m["challenge"] = b64(make([]byte, 32)) }}, sentinel: ErrVerification, step: "challenge"},
		{name: "origin", tweak: tweak{clientData: func(m map[string]any) { m["origin"] = "https://evil.example.com" }}, sentinel: ErrVerification, step: "origin"},
		{name: "origin-subdomain-not-listed", tweak: tweak{clientData: func(m map[string]any) { m["origin"] = "https://a.login.example.com" }}, sentinel: ErrVerification, step: "origin"},
		{name: "origin-port", tweak: tweak{clientData: func(m map[string]any) { m["origin"] = testOrigin + ":8443" }}, sentinel: ErrVerification, step: "origin"},
		{name: "cross-origin", tweak: tweak{clientData: func(m map[string]any) { m["crossOrigin"] = true; m["topOrigin"] = "https://top.example" }}, sentinel: ErrVerification, step: "cross-origin"},
		{name: "cross-origin-unlisted-top", config: func(c *Config) { c.TopOrigins = []string{"https://top.example"} },
			tweak: tweak{clientData: func(m map[string]any) { m["crossOrigin"] = true; m["topOrigin"] = "https://evil.example" }}, sentinel: ErrVerification, step: "topOrigin"},
		{name: "cross-origin-without-top", config: func(c *Config) { c.TopOrigins = []string{"https://top.example"} },
			tweak: tweak{clientData: func(m map[string]any) { m["crossOrigin"] = true }}, sentinel: ErrVerification, step: "cross-origin"},
		{name: "top-origin-without-cross-origin", config: func(c *Config) { c.TopOrigins = []string{"https://top.example"} },
			tweak: tweak{clientData: func(m map[string]any) { m["topOrigin"] = "https://top.example" }}, sentinel: ErrVerification, step: "topOrigin"},
		{name: "client-data-duplicate-member", tweak: tweak{response: func(m map[string]any) {
			r := m["response"].(map[string]any)
			r["clientDataJSON"] = b64([]byte(`{"type":"webauthn.create","type":"webauthn.create","challenge":"x","origin":"` + testOrigin + `"}`))
		}}, sentinel: ErrMalformed},
		{name: "rp-id-hash", tweak: tweak{rpID: "example.com"}, sentinel: ErrVerification, step: "rpIdHash"},
		{name: "user-present", tweak: tweak{authData: flipFlags(0, FlagUserPresent)}, sentinel: ErrVerification, step: "presence"},
		{name: "user-verified", tweak: tweak{authData: flipFlags(0, FlagUserVerified)}, sentinel: ErrVerification, step: "verification"},
		{name: "backup-state-without-eligible", tweak: tweak{authData: flipFlags(FlagBackupState, 0)}, sentinel: ErrVerification, step: "backup"},
		{name: "backup-forbidden", config: func(c *Config) { c.Policy.Backup = BackupForbidden },
			tweak: tweak{authData: flipFlags(FlagBackupEligible, 0)}, sentinel: ErrVerification, step: "backup-eligible"},
		{name: "algorithm-not-offered", alg: cose.AlgorithmEdDSA, config: func(c *Config) { c.Policy.Algorithms = []cose.Algorithm{cose.AlgorithmES256} }, sentinel: ErrVerification, step: "not offered"},
		{name: "raw-id-mismatch", tweak: tweak{response: func(m map[string]any) {
			id := b64([]byte("another credential id"))
			m["id"], m["rawId"] = id, id
		}}, sentinel: ErrVerification, step: "rawId"},
		{name: "authenticator-data-copy-mismatch", tweak: tweak{response: func(m map[string]any) {
			m["response"].(map[string]any)["authenticatorData"] = b64(make([]byte, 37))
		}}, sentinel: ErrMalformed, step: "authenticatorData"},
		{name: "authenticator-data-trailing", tweak: tweak{authData: func(d []byte) []byte { return append(d, 0) }}, sentinel: ErrMalformed},
		{name: "no-attested-data", tweak: tweak{authData: func(d []byte) []byte { d[32] &^= byte(FlagAttestedCredentialData); return d[:37] }}, sentinel: ErrMalformed},
		{name: "none-statement-not-empty", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["sig"] = []byte{1} }}, sentinel: ErrMalformed, step: "none"},
		{name: "packed-self-alg", format: "packed-self", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["alg"] = int(cose.AlgorithmRS256) }}, sentinel: ErrVerification, step: "alg"},
		{name: "packed-self-signature", format: "packed-self", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["sig"].([]byte)[10] ^= 1 }}, sentinel: ErrVerification, step: "signature"},
		{name: "packed-extra-member", format: "packed-self", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["ecdaaKeyId"] = []byte{1} }}, sentinel: ErrMalformed},
		{name: "packed-x5c-signature", format: "packed", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["sig"].([]byte)[10] ^= 1 }}, sentinel: ErrVerification, step: "signature"},
		{name: "packed-x5c-garbage", format: "packed", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["x5c"] = [][]byte{{1, 2, 3}} }}, sentinel: ErrMalformed, step: "x5c"},
		{name: "packed-cert-ou", format: "packed", tweak: tweak{statement: reissue(func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"Other"} })}, sentinel: ErrVerification, step: "subject"},
		{name: "packed-cert-ca", format: "packed", tweak: tweak{statement: reissue(func(c *x509.Certificate) { c.IsCA = true })}, sentinel: ErrVerification, step: "CA"},
		{name: "packed-cert-no-basic-constraints", format: "packed", tweak: tweak{statement: reissue(func(c *x509.Certificate) { c.BasicConstraintsValid = false })}, sentinel: ErrVerification, step: "Basic Constraints"},
		{name: "packed-cert-aaguid", format: "packed", tweak: tweak{statement: reissueAAGUID(AAGUID{9}, false)}, sentinel: ErrVerification, step: "AAGUID"},
		{name: "packed-cert-aaguid-critical", format: "packed", tweak: tweak{statement: reissueAAGUID(AAGUID{0x6b, 0x65, 0x79, 0x62, 0x6c, 0x61, 0x64, 0x65, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01}, true)}, sentinel: ErrVerification, step: "AAGUID"},
		{name: "packed-untrusted-root", format: "packed", config: func(c *Config) { c.Policy.TrustAttestation = TrustRoots(otherCA.root) }, sentinel: ErrVerification, step: "not trusted"},
		{name: "self-not-trusted-by-roots", format: "packed-self", config: func(c *Config) { c.Policy.TrustAttestation = TrustRoots(otherCA.root) }, sentinel: ErrVerification, step: "not trusted"},
		{name: "u2f-signature", format: "fido-u2f", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["sig"].([]byte)[10] ^= 1 }}, sentinel: ErrVerification, step: "signature"},
		{name: "u2f-two-certificates", format: "fido-u2f", tweak: tweak{statement: func(_ testing.TB, m map[string]any) {
			chain := m["x5c"].([][]byte)
			m["x5c"] = [][]byte{chain[0], chain[0]}
		}}, sentinel: ErrMalformed, step: "exactly one"},
		{name: "u2f-eddsa-credential", alg: cose.AlgorithmEdDSA, format: "packed", tweak: tweak{statement: func(_ testing.TB, m map[string]any) {
			delete(m, "alg")
			m["$fmt"] = "fido-u2f"
		}}, sentinel: ErrVerification, step: "ES256"},
		{name: "format-not-in-policy", format: "packed-self", config: func(c *Config) { c.Policy.AttestationFormats = []string{FormatNone} }, sentinel: ErrVerification, step: "policy"},
		{name: "format-tpm", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["$fmt"] = "tpm" }}, sentinel: ErrUnsupported, step: "tpm"},
		{name: "format-unknown", tweak: tweak{statement: func(_ testing.TB, m map[string]any) { m["$fmt"] = "example.com.custom" }}, sentinel: ErrUnsupported, step: "unknown"},
		{name: "credential-id-1024", sentinel: ErrMalformed},
		// A short rawId with a 1024-byte attested ID fails step 24 before the
		// attestation is verified or the trust callback runs (it would fail
		// with "not trusted" otherwise).
		{name: "credential-id-1024-authdata-only", config: func(c *Config) {
			c.Policy.TrustAttestation = func(context.Context, Attestation) error { return errors.New("trust callback reached") }
		}, tweak: tweak{response: func(m map[string]any) { m["id"], m["rawId"] = b64([]byte("short")), b64([]byte("short")) }}, sentinel: ErrVerification, step: "1023"},
		{name: "not-public-key", tweak: tweak{response: func(m map[string]any) { m["type"] = "password" }}, sentinel: ErrMalformed},
		{name: "id-not-raw-id", tweak: tweak{response: func(m map[string]any) { m["id"] = "AAAA" }}, sentinel: ErrMalformed},
		{name: "padded-base64", tweak: tweak{response: func(m map[string]any) { m["rawId"] = m["rawId"].(string) + "=" }}, sentinel: ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alg, format := tc.alg, tc.format
			if alg == 0 {
				alg = cose.AlgorithmES256
			}
			if format == "" {
				format = "none"
			}
			a := newSoft(t, alg, format)
			if strings.HasPrefix(tc.name, "credential-id-1024") {
				a.credentialID = bytes.Repeat([]byte{7}, 1024)
			}
			rp, _ := newTestRP(t, tc.config)
			options := beginRegistration(t, rp, testUser)
			_, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tc.tweak))
			expectStep(t, err, tc.sentinel, tc.step)
			// Every attempt consumes the ceremony.
			if _, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{})); !errors.Is(err, ErrChallenge) {
				t.Fatalf("second attempt: %v, want ErrChallenge", err)
			}
		})
	}
}

// reissue replaces the packed attestation chain with one whose leaf the
// edit changed, re-signing the statement.
func reissue(edit certificateTweak) func(testing.TB, map[string]any) {
	return func(t testing.TB, m map[string]any) {
		m["x5c"] = newTestAttestation(t, AAGUID{0x6b, 0x65, 0x79, 0x62, 0x6c, 0x61, 0x64, 0x65, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01}, edit).chain
	}
}

// reissueAAGUID replaces the AAGUID extension of the attestation leaf.
func reissueAAGUID(aaguid AAGUID, critical bool) func(testing.TB, map[string]any) {
	return func(t testing.TB, m map[string]any) {
		m["x5c"] = newTestAttestation(t, aaguid, func(c *x509.Certificate) {
			c.ExtraExtensions[0].Critical = critical
		}).chain
	}
}

// TestRegistrationCeremonyBinding checks the challenge store rules: wrong
// binding, wrong kind, expiry, cancellation and oversized bodies.
func TestRegistrationCeremonyBinding(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	rp, store := newTestRP(t, func(c *Config) { c.Clock = clock.Now; c.Timeout = time.Minute })
	a := newSoft(t, cose.AlgorithmES256, "none")

	options := beginRegistration(t, rp, testUser)
	response := a.register(t, options, testOrigin, tweak{})
	// A different session binding finds nothing and consumes nothing.
	if _, err := rp.FinishRegistration(ctx, options.ID, "another-session-binding", response); !errors.Is(err, ErrChallenge) {
		t.Fatalf("wrong binding: %v", err)
	}
	if store.Len() != 1 {
		t.Fatalf("wrong binding consumed the ceremony")
	}
	// The registration ceremony cannot finish a login.
	if _, err := rp.FinishLogin(ctx, options.ID, testBinding, response, lookupFor()); !errors.Is(err, ErrChallenge) {
		t.Fatalf("wrong kind: %v", err)
	}
	if store.Len() != 0 {
		t.Fatalf("wrong kind did not consume the ceremony")
	}

	// Expiry.
	options = beginRegistration(t, rp, testUser)
	clock.now = clock.now.Add(time.Minute)
	if _, err := rp.FinishRegistration(ctx, options.ID, testBinding, a.register(t, options, testOrigin, tweak{})); !errors.Is(err, ErrChallenge) {
		t.Fatalf("expired: %v", err)
	}

	// Cancellation.
	options = beginRegistration(t, rp, testUser)
	if err := rp.Cancel(ctx, options.ID, testBinding); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.FinishRegistration(ctx, options.ID, testBinding, a.register(t, options, testOrigin, tweak{})); !errors.Is(err, ErrChallenge) {
		t.Fatalf("cancelled: %v", err)
	}

	// Oversized and malformed bodies are rejected after consuming.
	options = beginRegistration(t, rp, testUser)
	if _, err := rp.FinishRegistration(ctx, options.ID, testBinding, bytes.Repeat([]byte{' '}, 65<<10)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized: %v", err)
	}
	for _, body := range []string{"", "{", `{"id":1}`, `{} {}`, `[]`} {
		options = beginRegistration(t, rp, testUser)
		if _, err := rp.FinishRegistration(ctx, options.ID, testBinding, []byte(body)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("body %q: %v", body, err)
		}
	}
	// Malformed ceremony IDs and bindings.
	for _, id := range []string{"", "short", strings.Repeat("A", 43) + "=", options.ID + "A"} {
		if _, err := rp.FinishRegistration(ctx, id, testBinding, nil); !errors.Is(err, ErrChallenge) {
			t.Fatalf("id %q: %v", id, err)
		}
	}
	if _, err := rp.FinishRegistration(ctx, options.ID, "short", nil); !errors.Is(err, ErrChallenge) {
		t.Fatalf("short binding: %v", err)
	}
}

// TestClientDataBOM checks that a UTF-8 byte order mark is stripped before
// parsing, as the UTF-8 decode step requires, while the signature still
// covers the raw bytes, and that invalid UTF-8 is rejected.
func TestClientDataBOM(t *testing.T) {
	rp, _ := newTestRP(t, nil)
	a := newSoft(t, cose.AlgorithmES256, "packed-self")
	bom := tweak{rawClient: func(c []byte) []byte { return append([]byte("\xef\xbb\xbf"), c...) }}
	options := beginRegistration(t, rp, testUser)
	registration, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, bom))
	if err != nil {
		t.Fatalf("registration with BOM: %v", err)
	}
	login := beginLogin(t, rp, testUser)
	if _, err := rp.FinishLogin(context.Background(), login.ID, testBinding, a.login(t, login, testOrigin, bom), lookupFor(registration.Credential)); err != nil {
		t.Fatalf("login with BOM: %v", err)
	}
	for _, bad := range []string{"{\"type\":\"\xff\"}", `{"type":"webauthn.get","challenge":"x","origin":"o"} x`, `{"type":1,"challenge":"x","origin":"o"}`,
		`{"type":"t","challenge":"x","origin":"o","crossOrigin":"true"}`, `{"type":"t","challenge":"x","origin":"o","topOrigin":""}`, `{"challenge":"x","origin":"o"}`} {
		if _, err := ParseClientData([]byte(bad)); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseClientData(%q) = %v, want ErrMalformed", bad, err)
		}
	}
}

// TestLoginRejects covers a negative case for every authentication
// verification step.
func TestLoginRejects(t *testing.T) {
	type setup struct {
		rp     *RelyingParty
		a      *softAuthenticator
		record Credential
	}
	cases := []struct {
		name     string
		config   func(*Config)
		prepare  func(*setup)
		user     []byte // nil: discoverable
		allow    bool
		tweak    tweak
		lookup   func(*setup) CredentialLookup
		sentinel error
		step     string
	}{
		{name: "type", user: testUser, tweak: tweak{clientData: func(m map[string]any) { m["type"] = "webauthn.create" }}, sentinel: ErrVerification, step: "type"},
		{name: "challenge", user: testUser, tweak: tweak{clientData: func(m map[string]any) { m["challenge"] = b64([]byte("x")) }}, sentinel: ErrVerification, step: "challenge"},
		{name: "origin", user: testUser, tweak: tweak{clientData: func(m map[string]any) { m["origin"] = "http://login.example.com" }}, sentinel: ErrVerification, step: "origin"},
		{name: "cross-origin", user: testUser, tweak: tweak{clientData: func(m map[string]any) { m["crossOrigin"] = true }}, sentinel: ErrVerification, step: "cross-origin"},
		{name: "rp-id-hash", user: testUser, tweak: tweak{rpID: "evil.example"}, sentinel: ErrVerification, step: "rpIdHash"},
		{name: "user-present", user: testUser, tweak: tweak{authData: flipFlags(0, FlagUserPresent)}, sentinel: ErrVerification, step: "presence"},
		{name: "user-verified", user: testUser, tweak: tweak{authData: flipFlags(0, FlagUserVerified)}, sentinel: ErrVerification, step: "verification"},
		{name: "backup-state-without-eligible", user: testUser, tweak: tweak{authData: flipFlags(FlagBackupState, 0)}, sentinel: ErrVerification, step: "backup state"},
		{name: "backup-eligibility-changed", user: testUser, tweak: tweak{authData: flipFlags(FlagBackupEligible, 0)}, sentinel: ErrVerification, step: "eligibility changed"},
		{name: "attested-data-in-assertion", user: testUser, tweak: tweak{authData: flipFlags(FlagAttestedCredentialData, 0)}, sentinel: ErrMalformed},
		{name: "signature", user: testUser, tweak: tweak{signature: func(s []byte) []byte { s[len(s)-1] ^= 1; return s }}, sentinel: ErrVerification, step: stepAssertion},
		{name: "signature-over-other-data", user: testUser, tweak: tweak{authData: func(d []byte) []byte { return d }, response: func(m map[string]any) {
			r := m["response"].(map[string]any)
			data, _ := decodeBase64URL(r["authenticatorData"].(string))
			data[36] ^= 1 // change the signed counter after signing
			r["authenticatorData"] = b64(data)
		}}, sentinel: ErrVerification, step: stepAssertion},
		{name: "counter-regression", user: testUser, prepare: func(s *setup) { s.record.SignCount = 10 }, sentinel: ErrCounter, step: "counter"},
		{name: "counter-zero-after-nonzero", user: testUser, prepare: func(s *setup) { s.record.SignCount = 10; s.a.count = ^uint32(0) }, sentinel: ErrCounter, step: "counter"},
		{name: "allow-credentials", user: testUser, allow: true, prepare: func(s *setup) { s.record.ID = []byte("different") }, sentinel: ErrVerification, step: "allowCredentials"},
		{name: "user-handle-mismatch", user: []byte("someone else"), sentinel: ErrVerification, step: "userHandle"},
		{name: "discoverable-without-user-handle", tweak: tweak{response: func(m map[string]any) {
			delete(m["response"].(map[string]any), "userHandle")
		}}, sentinel: ErrVerification, step: "userHandle"},
		{name: "record-owned-by-another-user", user: testUser, prepare: func(s *setup) { s.record.UserHandle = []byte("mallory") }, sentinel: ErrVerification, step: stepAssertion},
		{name: "record-other-rp", user: testUser, prepare: func(s *setup) { s.record.RPID = "other.example" }, sentinel: ErrVerification, step: stepAssertion},
		{name: "record-empty-rp", user: testUser, prepare: func(s *setup) { s.record.RPID = "" }, sentinel: ErrVerification, step: stepAssertion},
		{name: "record-missing", user: testUser, lookup: func(*setup) CredentialLookup { return lookupFor() }, sentinel: ErrVerification, step: stepAssertion},
		{name: "record-algorithm-mismatch", user: testUser, prepare: func(s *setup) { s.record.Algorithm = cose.AlgorithmRS256 }, sentinel: ErrVerification, step: "algorithm"},
		{name: "record-key-corrupt", user: testUser, prepare: func(s *setup) { s.record.PublicKey = []byte{0xa0} }, sentinel: ErrMalformed, step: "stored"},
		{name: "backup-forbidden", user: testUser, config: func(c *Config) { c.Policy.Backup = BackupForbidden },
			prepare: func(s *setup) { s.record.BackupEligible = true }, tweak: tweak{authData: flipFlags(FlagBackupEligible, 0)}, sentinel: ErrVerification, step: "policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rp, _ := newTestRP(t, tc.config)
			a := newSoft(t, cose.AlgorithmES256, "none")
			options := beginRegistration(t, rp, testUser)
			registration, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
			if err != nil {
				t.Fatal(err)
			}
			s := &setup{rp: rp, a: a, record: registration.Credential}
			if tc.prepare != nil {
				tc.prepare(s)
			}
			var allow []Credential
			if tc.allow {
				allow = append(allow, s.record)
			}
			login := beginLogin(t, rp, tc.user, allow...)
			lookup := lookupFor(s.record)
			if tc.lookup != nil {
				lookup = tc.lookup(s)
			}
			if tc.name == "allow-credentials" {
				lookup = lookupFor(registration.Credential)
			}
			_, err = rp.FinishLogin(context.Background(), login.ID, testBinding, a.login(t, login, testOrigin, tc.tweak), lookup)
			expectStep(t, err, tc.sentinel, tc.step)
		})
	}
}

// TestCounterRules covers the signature counter rules: zero on both sides is
// valid, an increase is valid, and a regression is reported or rejected.
func TestCounterRules(t *testing.T) {
	for _, policy := range []CounterPolicy{CounterReject, CounterReport} {
		rp, _ := newTestRP(t, func(c *Config) { c.Policy.Counter = policy })
		a := newSoft(t, cose.AlgorithmEdDSA, "none")
		options := beginRegistration(t, rp, testUser)
		registration, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
		if err != nil {
			t.Fatal(err)
		}
		record := registration.Credential

		// Zero stays zero: authenticators without counters (synced passkeys).
		a.count = ^uint32(0) // login increments to 0
		login := beginLogin(t, rp, testUser)
		result, err := rp.FinishLogin(context.Background(), login.ID, testBinding, a.login(t, login, testOrigin, tweak{}), lookupFor(record))
		if err != nil || result.CounterAnomaly || result.Credential.SignCount != 0 {
			t.Fatalf("zero counter: %v %+v", err, result)
		}

		// Regression.
		record.SignCount = 5
		a.count = 2
		login = beginLogin(t, rp, testUser)
		result, err = rp.FinishLogin(context.Background(), login.ID, testBinding, a.login(t, login, testOrigin, tweak{}), lookupFor(record))
		switch policy {
		case CounterReject:
			if !errors.Is(err, ErrCounter) {
				t.Fatalf("reject policy: %v", err)
			}
		case CounterReport:
			if err != nil || !result.CounterAnomaly || result.Credential.SignCount != 5 || result.PreviousSignCount != 5 {
				t.Fatalf("report policy: %v %+v", err, result)
			}
		}
	}
}

// TestBackupStateAndUVUpdates checks the record updates of §7.2.
func TestBackupStateAndUVUpdates(t *testing.T) {
	rp, _ := newTestRP(t, func(c *Config) { c.Policy.UserVerification = UserVerificationPreferred })
	a := newSoft(t, cose.AlgorithmES256, "none")
	a.flags = FlagUserPresent | FlagBackupEligible
	options := beginRegistration(t, rp, testUser)
	registration, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
	if err != nil {
		t.Fatal(err)
	}
	if registration.Credential.UVInitialized || !registration.Credential.BackupEligible || registration.Credential.BackupState {
		t.Fatalf("record: %+v", registration.Credential)
	}
	a.flags = FlagUserPresent | FlagUserVerified | FlagBackupEligible | FlagBackupState
	login := beginLogin(t, rp, testUser)
	result, err := rp.FinishLogin(context.Background(), login.ID, testBinding, a.login(t, login, testOrigin, tweak{}), lookupFor(registration.Credential))
	if err != nil {
		t.Fatal(err)
	}
	if !result.BackupStateChanged || !result.Credential.BackupState || !result.Credential.UVInitialized {
		t.Fatalf("updates not applied: %+v", result)
	}
}

// TestRequiredUVOverride checks a per-ceremony UV override above a
// preferred policy (step-up authentication).
func TestRequiredUVOverride(t *testing.T) {
	rp, _ := newTestRP(t, func(c *Config) { c.Policy.UserVerification = UserVerificationPreferred })
	a := newSoft(t, cose.AlgorithmES256, "none")
	options := beginRegistration(t, rp, testUser)
	registration, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{}))
	if err != nil {
		t.Fatal(err)
	}
	a.flags = FlagUserPresent
	login, err := rp.BeginLogin(context.Background(), LoginRequest{Binding: testBinding, UserHandle: testUser, UserVerification: UserVerificationRequired})
	if err != nil {
		t.Fatal(err)
	}
	if login.Options.PublicKey.UserVerification != UserVerificationRequired {
		t.Fatal("override not sent")
	}
	_, err = rp.FinishLogin(context.Background(), login.ID, testBinding, a.login(t, login, testOrigin, tweak{}), lookupFor(registration.Credential))
	expectStep(t, err, ErrVerification, "verification")
}

// TestLookupErrorsPropagate checks that infrastructure errors from the
// lookup are returned as they are.
func TestLookupErrorsPropagate(t *testing.T) {
	rp, _ := newTestRP(t, nil)
	a := newSoft(t, cose.AlgorithmES256, "none")
	options := beginRegistration(t, rp, testUser)
	if _, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, testOrigin, tweak{})); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("database unavailable")
	login := beginLogin(t, rp, testUser)
	_, err := rp.FinishLogin(context.Background(), login.ID, testBinding, a.login(t, login, testOrigin, tweak{}),
		func(context.Context, []byte, []byte) (*Credential, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("error = %v", err)
	}
	if _, err := rp.FinishLogin(context.Background(), login.ID, testBinding, nil, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil lookup: %v", err)
	}
}

// TestRelatedAndNativeOrigins checks related origins, native app origins and
// the well-known document.
func TestRelatedAndNativeOrigins(t *testing.T) {
	native := "android:apk-key-hash:" + b64(sha256.New().Sum(nil))
	rp, _ := newTestRP(t, func(c *Config) {
		c.ID = "example.com"
		c.Origins = []string{"https://example.com", "https://login.example.com", native}
		c.RelatedOrigins = []string{"https://example.co.uk"}
	})
	var doc struct{ Origins []string }
	if err := json.Unmarshal(rp.WellKnown(), &doc); err != nil || len(doc.Origins) != 3 || doc.Origins[2] != "https://example.co.uk" {
		t.Fatalf("WellKnown = %s (%v)", rp.WellKnown(), err)
	}
	for _, origin := range []string{"https://example.co.uk", native, "https://login.example.com"} {
		a := newSoft(t, cose.AlgorithmES256, "none")
		options := beginRegistration(t, rp, testUser)
		if _, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, a.register(t, options, origin, tweak{})); err != nil {
			t.Fatalf("origin %s: %v", origin, err)
		}
	}
}
