package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/picatz/doh/internal/cose"
)

func TestNewValidatesConfig(t *testing.T) {
	store, _ := NewMemoryChallengeStore(10)
	bad := []Config{
		{ID: "example.com"}, // no store
		{ID: "", Store: store},
		{ID: "Example.com", Store: store},
		{ID: "127.0.0.1", Store: store},
		{ID: "[::1]", Store: store},
		{ID: "com", Store: store},
		{ID: "-bad.example", Store: store},
		{ID: "exa mple.com", Store: store},
		{ID: "example.com", Store: store, Origins: []string{"https://evil.com"}},
		{ID: "example.com", Store: store, Origins: []string{"http://example.com"}},
		{ID: "example.com", Store: store, Origins: []string{"https://example.com/"}},
		{ID: "example.com", Store: store, Origins: []string{"https://example.com:443"}},
		{ID: "example.com", Store: store, Origins: []string{"https://EXAMPLE.com"}},
		{ID: "example.com", Store: store, Origins: []string{"https://user@example.com"}},
		{ID: "example.com", Store: store, Origins: []string{"https://example.com?x"}},
		{ID: "example.com", Store: store, Origins: []string{"https://notexample.com"}},
		{ID: "example.com", Store: store, Origins: []string{"android://x"}},
		{ID: "example.com", Store: store, RelatedOrigins: []string{"http://example.org"}},
		{ID: "example.com", Store: store, RelatedOrigins: []string{"android:apk-key-hash:x"}},
		{ID: "example.com", Store: store, TopOrigins: []string{"top"}},
		{ID: "example.com", Store: store, Timeout: time.Millisecond},
		{ID: "example.com", Store: store, Timeout: time.Hour},
		{ID: "example.com", Store: store, MaxResponseBytes: 10},
		{ID: "example.com", Store: store, MaxResponseBytes: 2 << 20},
		{ID: "example.com", Store: store, Policy: Policy{UserVerification: "always"}},
		{ID: "example.com", Store: store, Policy: Policy{Algorithms: []cose.Algorithm{-65535}}},
		{ID: "example.com", Store: store, Policy: Policy{Algorithms: []cose.Algorithm{cose.AlgorithmES256, cose.AlgorithmES256}}},
		{ID: "example.com", Store: store, Policy: Policy{AttestationFormats: []string{FormatTPM}}},
		{ID: "example.com", Store: store, Policy: Policy{Backup: 7}},
		{ID: "example.com", Store: store, Policy: Policy{Counter: 7}},
	}
	for i, config := range bad {
		if _, err := New(config); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("case %d (%+v): error = %v, want ErrInvalidInput", i, config.Origins, err)
		}
	}
	good := []Config{
		{ID: "example.com", Store: store},
		{ID: "localhost", Store: store, Origins: []string{"http://localhost:8080", "https://localhost"}},
		// A subdomain of localhost is a secure context too, so it may use HTTP,
		// as parseOrigin already allowed for origins under it.
		{ID: "app.localhost", Store: store, Origins: []string{"http://app.localhost:3000", "http://api.app.localhost"}},
		{ID: "example.com", Store: store, Origins: []string{"https://example.com", "https://a.b.example.com:8443"}, RelatedOrigins: []string{"https://example.de"}},
		{ID: "xn--bcher-kva.example", Store: store},
	}
	for i, config := range good {
		if _, err := New(config); err != nil {
			t.Errorf("good case %d: %v", i, err)
		}
	}
}

// TestBeginValidatesRequests checks begin-time bounds and the JSON shape of
// the options against the WebAuthn Level 3 serialization.
func TestBeginValidatesRequests(t *testing.T) {
	rp, store := newTestRP(t, nil)
	ctx := context.Background()
	user := UserEntity{ID: testUser, Name: "alice"}
	bad := []RegistrationRequest{
		{Binding: "short", User: user},
		{Binding: testBinding, User: UserEntity{Name: "alice"}},
		{Binding: testBinding, User: UserEntity{ID: make([]byte, 65), Name: "alice"}},
		{Binding: testBinding, User: UserEntity{ID: testUser}},
		{Binding: testBinding, User: UserEntity{ID: testUser, Name: strings.Repeat("a", 257)}},
		{Binding: testBinding, User: user, ResidentKey: "always"},
		{Binding: testBinding, User: user, Attachment: "usb"},
		{Binding: testBinding, User: user, Attestation: "enterprise"},
		{Binding: testBinding, User: user, UserVerification: "maybe"},
		{Binding: testBinding, User: user, Hints: []Hint{HintHybrid, HintHybrid}},
		{Binding: testBinding, User: user, Hints: []Hint{"phone"}},
		{Binding: testBinding, User: user, ExcludeCredentials: []CredentialDescriptor{{ID: nil}}},
		{Binding: testBinding, User: user, ExcludeCredentials: make([]CredentialDescriptor, 257)},
	}
	for i, request := range bad {
		if _, err := rp.BeginRegistration(ctx, request); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("registration case %d: %v", i, err)
		}
	}
	for i, request := range []LoginRequest{{Binding: "x"}, {Binding: testBinding, UserHandle: make([]byte, 65)}, {Binding: testBinding, Mediation: "silent"}} {
		if _, err := rp.BeginLogin(ctx, request); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("login case %d: %v", i, err)
		}
	}
	if store.Len() != 0 {
		t.Fatalf("invalid requests stored ceremonies")
	}

	options, err := rp.BeginRegistration(ctx, RegistrationRequest{Binding: testBinding, User: UserEntity{ID: []byte{0xfb, 0xff}, Name: "alice", DisplayName: "Alice"},
		ResidentKey: ResidentKeyRequired, Hints: []Hint{HintSecurityKey}, Attestation: AttestationConveyanceDirect,
		ExcludeCredentials: []CredentialDescriptor{{ID: []byte{1}, Transports: []Transport{TransportUSB}}},
		Extensions:         &ExtensionInputs{CredProps: true, PRF: &PRFInputs{Eval: &PRFValues{First: []byte{1}}}}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(options)
	var shape map[string]any
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	pk := shape["options"].(map[string]any)["publicKey"].(map[string]any)
	checks := map[string]any{
		"rp":                     map[string]any{"id": testRPID, "name": "Example"},
		"user":                   map[string]any{"id": "-_8", "name": "alice", "displayName": "Alice"},
		"attestation":            "direct",
		"hints":                  []any{"security-key"},
		"timeout":                float64(300000),
		"authenticatorSelection": map[string]any{"residentKey": "required", "requireResidentKey": true, "userVerification": "required"},
		"excludeCredentials":     []any{map[string]any{"type": "public-key", "id": "AQ", "transports": []any{"usb"}}},
		"extensions":             map[string]any{"credProps": true, "prf": map[string]any{"eval": map[string]any{"first": "AQ"}}},
		"pubKeyCredParams":       []any{map[string]any{"type": "public-key", "alg": float64(-7)}, map[string]any{"type": "public-key", "alg": float64(-8)}, map[string]any{"type": "public-key", "alg": float64(-257)}},
	}
	for key, want := range checks {
		got, _ := json.Marshal(pk[key])
		expected, _ := json.Marshal(want)
		if string(got) != string(expected) {
			t.Errorf("%s = %s, want %s", key, got, expected)
		}
	}
	if challenge, _ := pk["challenge"].(string); len(challenge) != 43 {
		t.Errorf("challenge %q is not 32 base64url bytes", challenge)
	}

	login, err := rp.BeginLogin(ctx, LoginRequest{Binding: testBinding, Mediation: MediationConditional})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(login)
	if !strings.Contains(string(encoded), `"mediation":"conditional"`) || !strings.Contains(string(encoded), `"rpId":"login.example.com"`) || strings.Contains(string(encoded), "allowCredentials") {
		t.Errorf("login options JSON = %s", encoded)
	}
}

// TestChallengesAreUnique checks that challenges and ceremony IDs come from
// a CSPRNG and never repeat across many ceremonies.
func TestChallengesAreUnique(t *testing.T) {
	rp, _ := newTestRP(t, nil)
	seen := map[string]bool{}
	for range 200 {
		options, err := rp.BeginLogin(context.Background(), LoginRequest{Binding: testBinding})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{options.ID, options.Options.PublicKey.Challenge.String()} {
			if seen[v] {
				t.Fatal("repeated challenge or ceremony ID")
			}
			seen[v] = true
		}
	}
}

func TestMemoryChallengeStore(t *testing.T) {
	if _, err := NewMemoryChallengeStore(0); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("capacity 0 accepted")
	}
	store, _ := NewMemoryChallengeStore(2)
	ctx := context.Background()
	now := time.Now()
	key := CeremonyKey{Tenant: "a", ID: "1"}
	ceremony := Ceremony{Kind: CeremonyLogin, Challenge: []byte{1, 2, 3}, AllowCredentials: [][]byte{{9}}, Expires: now.Add(time.Minute)}
	if err := store.Put(ctx, key, ceremony); err != nil {
		t.Fatal(err)
	}
	ceremony.Challenge[0], ceremony.AllowCredentials[0][0] = 7, 7 // caller mutation must not leak in
	if err := store.Put(ctx, key, ceremony); !errors.Is(err, ErrChallenge) {
		t.Fatalf("duplicate Put: %v", err)
	}
	// Tenants are separate namespaces.
	if err := store.Put(ctx, CeremonyKey{Tenant: "b", ID: "1"}, ceremony); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, CeremonyKey{Tenant: "c", ID: "1"}, ceremony); !errors.Is(err, ErrCapacity) {
		t.Fatalf("over capacity: %v", err)
	}
	got, err := store.Consume(ctx, key, now)
	if err != nil || got.Challenge[0] != 1 || got.AllowCredentials[0][0] != 9 {
		t.Fatalf("Consume = %+v, %v", got, err)
	}
	if _, err := store.Consume(ctx, key, now); !errors.Is(err, ErrChallenge) {
		t.Fatalf("second Consume: %v", err)
	}
	if _, err := store.Consume(ctx, CeremonyKey{Tenant: "b", ID: "1"}, now.Add(time.Hour)); !errors.Is(err, ErrChallenge) {
		t.Fatalf("expired Consume: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Put(cancelled, key, ceremony); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Put: %v", err)
	}
	// Expired entries are swept when the store is full.
	full, _ := NewMemoryChallengeStore(1)
	_ = full.Put(ctx, key, Ceremony{Expires: now.Add(-time.Second)})
	if err := full.Put(ctx, CeremonyKey{ID: "2"}, Ceremony{Expires: now.Add(time.Minute)}); err != nil {
		t.Fatalf("sweep: %v", err)
	}
}

// TestConcurrentFinishOneWinner checks single-use semantics under
// concurrency: of many simultaneous finishes, exactly one succeeds.
func TestConcurrentFinishOneWinner(t *testing.T) {
	rp, _ := newTestRP(t, nil)
	a := newSoft(t, cose.AlgorithmES256, "none")
	options := beginRegistration(t, rp, testUser)
	response := a.register(t, options, testOrigin, tweak{})
	var wins, challenges atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, err := rp.FinishRegistration(context.Background(), options.ID, testBinding, response)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrChallenge):
				challenges.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || challenges.Load() != 15 {
		t.Fatalf("wins = %d, consumed = %d", wins.Load(), challenges.Load())
	}
}

func TestVerificationErrorFormat(t *testing.T) {
	err := failure(CeremonyLogin, ErrVerification, specAssertion, "assertion signature is invalid")
	want := "webauthn: authentication: assertion signature is invalid (" + specAssertion + ")"
	if err.Error() != want || !errors.Is(err, ErrVerification) {
		t.Fatalf("Error() = %q", err.Error())
	}
	if !errors.Is(ErrUnsupported, errors.ErrUnsupported) {
		t.Fatal("ErrUnsupported does not match errors.ErrUnsupported")
	}
}

func TestBase64URLAndAAGUID(t *testing.T) {
	var b Base64URL
	for _, bad := range []string{`"AQ=="`, `"AQ+/"`, `1`, `"A"`, `"AR"`} {
		if err := json.Unmarshal([]byte(bad), &b); err == nil {
			t.Errorf("Base64URL accepted %s", bad)
		}
	}
	if err := json.Unmarshal([]byte(`"-_8"`), &b); err != nil || string(b) != "\xfb\xff" {
		t.Fatalf("Base64URL decode: %v %x", err, b)
	}
	a := AAGUID{0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54, 0xa8}
	if a.String() != "cb69481e-8ff7-4039-93ec-0a2729a154a8" || a.IsZero() {
		t.Fatalf("AAGUID.String = %s", a)
	}
	var back AAGUID
	if err := back.UnmarshalText([]byte(a.String())); err != nil || back != a {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if err := back.UnmarshalText([]byte("cb69481e8ff7403993ec0a2729a154a8")); err != nil || back != a {
		t.Fatalf("UnmarshalText plain: %v", err)
	}
	if err := back.UnmarshalText([]byte("zz")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("UnmarshalText bad: %v", err)
	}
}
