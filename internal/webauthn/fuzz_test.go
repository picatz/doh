package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/picatz/doh/internal/cose"
)

// fuzzChallenge is the fixed challenge of fuzzed ceremonies.
var fuzzChallenge = bytes.Repeat([]byte{0x42}, 32)

func addVectorSeeds(f *testing.F, field string, login bool) {
	v := loadVectors(f)
	for _, vector := range v.Vectors {
		source := vector.Registration
		if login {
			source = vector.Login
		}
		if s, ok := source[field]; ok {
			f.Add(unhex(f, s))
		}
	}
}

func FuzzParseClientData(f *testing.F) {
	addVectorSeeds(f, "clientDataJSON", false)
	addVectorSeeds(f, "clientDataJSON", true)
	f.Add([]byte(`{"type":"webauthn.get","type":"x"}`))
	f.Add([]byte("\xef\xbb\xbf{}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseClientData(data)
		if err == nil && (c == nil || (c.TopOrigin == "" && bytes.Contains(data, []byte(`"topOrigin":""`)))) {
			t.Fatalf("accepted inconsistent client data %q", data)
		}
		if err != nil && !errors.Is(err, ErrMalformed) {
			t.Fatalf("unclassified error %v", err)
		}
	})
}

func FuzzParseAuthenticatorData(f *testing.F) {
	addVectorSeeds(f, "authenticatorData", true)
	for _, vector := range loadVectors(f).Vectors {
		if object, err := ParseAttestationObject(unhex(f, vector.Registration["attestationObject"])); err == nil {
			f.Add(object.AuthData)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		auth, err := ParseAuthenticatorData(data)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("unclassified error %v", err)
			}
			return
		}
		if (auth.Attested != nil) != auth.Flags.Has(FlagAttestedCredentialData) || (auth.Extensions != nil) != auth.Flags.Has(FlagExtensionData) {
			t.Fatalf("flags and parsed data disagree for %x", data)
		}
		if auth.Attested != nil {
			_, _ = ParsePublicKey(auth.Attested.PublicKey)
		}
	})
}

func FuzzParseAttestationObject(f *testing.F) {
	addVectorSeeds(f, "attestationObject", false)
	f.Fuzz(func(t *testing.T, data []byte) {
		object, err := ParseAttestationObject(data)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("unclassified error %v", err)
			}
			return
		}
		auth, err := ParseAuthenticatorData(object.AuthData)
		if err != nil || auth.Attested == nil {
			return
		}
		key, err := ParsePublicKey(auth.Attested.PublicKey)
		if err != nil {
			return
		}
		// Statement verification must classify every failure.
		_, err = verifyStatement(object, auth, key, make([]byte, 32))
		if err != nil && !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrVerification) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unclassified statement error %v", err)
		}
	})
}

func FuzzParsePublicKey(f *testing.F) {
	for _, vector := range loadVectors(f).Vectors {
		if object, err := ParseAttestationObject(unhex(f, vector.Registration["attestationObject"])); err == nil {
			if auth, err := ParseAuthenticatorData(object.AuthData); err == nil && auth.Attested != nil {
				f.Add(auth.Attested.PublicKey)
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParsePublicKey(data)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unclassified error %v", err)
			}
			return
		}
		if key.Algorithm.Available() != nil || key.Verify([]byte("m"), []byte("not a signature")) == nil {
			t.Fatalf("parsed key %v verified garbage", key.Algorithm)
		}
	})
}

// FuzzFinishRegistration drives whole registration ceremonies with mutated
// responses. Every outcome must be success or a classified error.
func FuzzFinishRegistration(f *testing.F) {
	rp, _ := newTestRP(f, func(c *Config) { c.Policy.UserVerification = UserVerificationPreferred })
	options := &RegistrationOptions{Options: CredentialCreationOptions{PublicKey: CreationOptions{
		RP: RelyingPartyEntity{ID: testRPID}, User: UserEntity{ID: testUser}, Challenge: fuzzChallenge}}}
	for _, format := range []string{"none", "packed-self", "packed", "fido-u2f"} {
		f.Add(newSoft(f, cose.AlgorithmES256, format).register(f, options, testOrigin, tweak{}))
	}
	f.Add(newSoft(f, cose.AlgorithmEdDSA, "packed-self").register(f, options, testOrigin, tweak{}))
	f.Fuzz(func(t *testing.T, response []byte) {
		id := inject(t, rp, Ceremony{Kind: CeremonyRegistration, Challenge: fuzzChallenge, UserHandle: testUser,
			UserVerification: UserVerificationPreferred, Algorithms: defaultAlgorithms})
		registration, err := rp.FinishRegistration(context.Background(), id, testBinding, response)
		if err == nil {
			if _, err := ParsePublicKey(registration.Credential.PublicKey); err != nil || len(registration.Credential.ID) > maxCredentialID {
				t.Fatalf("accepted an unusable credential: %v", err)
			}
			return
		}
		if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrVerification) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unclassified error %v", err)
		}
	})
}

// FuzzFinishLogin drives authentication ceremonies with mutated responses
// against a fixed credential record.
func FuzzFinishLogin(f *testing.F) {
	rp, _ := newTestRP(f, func(c *Config) {
		c.Policy.UserVerification = UserVerificationPreferred
		c.Policy.Counter = CounterReport
	})
	a := newSoft(f, cose.AlgorithmES256, "none")
	registration := &RegistrationOptions{Options: CredentialCreationOptions{PublicKey: CreationOptions{
		RP: RelyingPartyEntity{ID: testRPID}, User: UserEntity{ID: testUser}, Challenge: fuzzChallenge}}}
	id := inject(f, rp, Ceremony{Kind: CeremonyRegistration, Challenge: fuzzChallenge, UserHandle: testUser,
		UserVerification: UserVerificationPreferred, Algorithms: defaultAlgorithms})
	created, err := rp.FinishRegistration(context.Background(), id, testBinding, a.register(f, registration, testOrigin, tweak{}))
	if err != nil {
		f.Fatal(err)
	}
	login := &LoginOptions{Options: CredentialRequestOptions{PublicKey: RequestOptions{RPID: testRPID, Challenge: fuzzChallenge}}}
	f.Add(a.login(f, login, testOrigin, tweak{}))
	f.Fuzz(func(t *testing.T, response []byte) {
		id := inject(t, rp, Ceremony{Kind: CeremonyLogin, Challenge: fuzzChallenge, UserVerification: UserVerificationPreferred})
		result, err := rp.FinishLogin(context.Background(), id, testBinding, response, lookupFor(created.Credential))
		if err == nil {
			if !bytes.Equal(result.UserHandle, testUser) {
				t.Fatalf("authenticated the wrong user %q", result.UserHandle)
			}
			return
		}
		if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrVerification) && !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrCredential) {
			t.Fatalf("unclassified error %v", err)
		}
	})
}

func responseSeeds(f *testing.F, build func(id, raw string) string) {
	raw := bytes.Repeat([]byte{7}, 16)
	id := Base64URL(raw).String()
	valid := build(id, id)
	f.Add([]byte(valid))
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))
	f.Add([]byte(valid + "x"))
	f.Add([]byte(valid[:len(valid)/2]))
	f.Add([]byte(build("AAAA", id)))
	f.Add([]byte(build(id, "!!!")))
	f.Add([]byte(build(id, strings.Repeat("A", 4000))))
	f.Add([]byte(`{"type":"public-key","type":"public-key"}`))
}

// FuzzParseRegistrationResponse checks that accepted responses satisfy the
// documented invariants and survive a marshal/parse round trip unchanged,
// and that every rejection is a classified ErrMalformed with a nil result.
func FuzzParseRegistrationResponse(f *testing.F) {
	responseSeeds(f, func(id, raw string) string {
		return `{"id":"` + id + `","rawId":"` + raw + `","type":"public-key","response":{"clientDataJSON":"AQID","attestationObject":"BAUG"},"clientExtensionResults":{}}`
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseRegistrationResponse(data)
		if err != nil {
			if r != nil || !errors.Is(err, ErrMalformed) {
				t.Fatalf("rejection returned %v, %v", r, err)
			}
			return
		}
		if r == nil || r.Type != "public-key" || len(r.RawID) == 0 || len(r.RawID) > maxCredentialID ||
			r.ID != Base64URL(r.RawID).String() || len(r.Response.ClientDataJSON) == 0 || len(r.Response.AttestationObject) == 0 {
			t.Fatalf("accepted an invalid response %+v", r)
		}
		again, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		second, err := ParseRegistrationResponse(again)
		if err != nil || !reflect.DeepEqual(r, second) {
			t.Fatalf("round trip changed the response: %v\n%+v\n%+v", err, r, second)
		}
	})
}

// FuzzParseAuthenticationResponse is the login counterpart.
func FuzzParseAuthenticationResponse(f *testing.F) {
	responseSeeds(f, func(id, raw string) string {
		return `{"id":"` + id + `","rawId":"` + raw + `","type":"public-key","response":{"clientDataJSON":"AQID","authenticatorData":"BAUG","signature":"BwgJ","userHandle":"Cg"},"clientExtensionResults":{}}`
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseAuthenticationResponse(data)
		if err != nil {
			if r != nil || !errors.Is(err, ErrMalformed) {
				t.Fatalf("rejection returned %v, %v", r, err)
			}
			return
		}
		if r == nil || r.Type != "public-key" || len(r.RawID) == 0 || len(r.RawID) > maxCredentialID ||
			r.ID != Base64URL(r.RawID).String() || len(r.Response.ClientDataJSON) == 0 ||
			len(r.Response.AuthenticatorData) == 0 || len(r.Response.Signature) == 0 {
			t.Fatalf("accepted an invalid response %+v", r)
		}
		again, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		second, err := ParseAuthenticationResponse(again)
		if err != nil || !reflect.DeepEqual(r, second) {
			t.Fatalf("round trip changed the response: %v\n%+v\n%+v", err, r, second)
		}
	})
}

func TestParseResponsesMalformed(t *testing.T) {
	id := Base64URL([]byte{1, 2, 3}).String()
	big := Base64URL(make([]byte, maxCredentialID+1)).String()
	wrap := func(typ, id, raw, resp string) string {
		return `{"id":"` + id + `","rawId":"` + raw + `","type":"` + typ + `","response":` + resp + `}`
	}
	goodReg := `{"clientDataJSON":"AQID","attestationObject":"BAUG"}`
	goodAuth := `{"clientDataJSON":"AQID","authenticatorData":"BAUG","signature":"BwgJ"}`
	// Rejected by both parsers for the same envelope reason.
	for name, in := range map[string]string{
		"empty":               ``,
		"null":                `null`,
		"array":               `[]`,
		"trailing data":       wrap("public-key", id, id, goodReg) + `{}`,
		"wrong type":          wrap("password", id, id, goodReg),
		"id mismatch":         wrap("public-key", "AAAA", id, goodReg),
		"bad base64 rawId":    wrap("public-key", id, "!!!", goodReg),
		"empty rawId":         wrap("public-key", "", "", goodReg),
		"oversized rawId":     wrap("public-key", big, big, goodReg),
		"response not object": wrap("public-key", id, id, `"x"`),
		"id wrong json type":  `{"id":1,"rawId":"` + id + `","type":"public-key","response":` + goodReg + `}`,
		"duplicate member":    `{"type":"public-key","type":"public-key"}`,
	} {
		if _, err := ParseRegistrationResponse([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("registration %s: err = %v, want ErrMalformed", name, err)
		}
		if _, err := ParseAuthenticationResponse([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("authentication %s: err = %v, want ErrMalformed", name, err)
		}
	}
	for name, resp := range map[string]string{
		"no clientData":    `{"attestationObject":"BAUG"}`,
		"no attestation":   `{"clientDataJSON":"AQID"}`,
		"empty clientData": `{"clientDataJSON":"","attestationObject":"BAUG"}`,
	} {
		if _, err := ParseRegistrationResponse([]byte(wrap("public-key", id, id, resp))); !errors.Is(err, ErrMalformed) {
			t.Errorf("registration %s: err = %v, want ErrMalformed", name, err)
		}
	}
	for name, resp := range map[string]string{
		"no clientData": `{"authenticatorData":"BAUG","signature":"BwgJ"}`,
		"no authData":   `{"clientDataJSON":"AQID","signature":"BwgJ"}`,
		"no signature":  `{"clientDataJSON":"AQID","authenticatorData":"BAUG"}`,
	} {
		if _, err := ParseAuthenticationResponse([]byte(wrap("public-key", id, id, resp))); !errors.Is(err, ErrMalformed) {
			t.Errorf("authentication %s: err = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := ParseRegistrationResponse([]byte(wrap("public-key", id, id, goodReg))); err != nil {
		t.Errorf("valid registration rejected: %v", err)
	}
	if _, err := ParseAuthenticationResponse([]byte(wrap("public-key", id, id, goodAuth))); err != nil {
		t.Errorf("valid authentication rejected: %v", err)
	}
}
