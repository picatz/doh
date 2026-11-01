package webauthn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/picatz/cbor"
	"github.com/picatz/doh/internal/cose"
)

// softAuthenticator is a deterministic software authenticator used ONLY to
// produce test responses. It is not a CTAP implementation, a browser or a
// verifier, and it lives only in _test.go files.
type softAuthenticator struct {
	algorithm    cose.Algorithm
	signer       crypto.Signer
	credentialID []byte
	userHandle   []byte
	aaguid       AAGUID
	count        uint32
	flags        Flags
	format       string // "none", "packed-self", "packed", "fido-u2f"
	attestation  *testAttestation
}

// testAttestation is an attestation certificate and key issued by a test CA.
type testAttestation struct {
	key   *ecdsa.PrivateKey
	chain [][]byte // leaf first
	root  *x509.CertPool
}

// fixedP256 returns a P-256 key derived deterministically from label.
func fixedP256(t testing.TB, label string) *ecdsa.PrivateKey {
	t.Helper()
	for counter := byte(0); ; counter++ {
		seed := sha256.Sum256(append([]byte("relyingparty test key "+label), counter))
		key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
		if err == nil {
			return key
		}
	}
}

func fixedEd25519(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("relyingparty test key " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func newSoft(t testing.TB, algorithm cose.Algorithm, format string) *softAuthenticator {
	t.Helper()
	a := &softAuthenticator{algorithm: algorithm, format: format, flags: FlagUserPresent | FlagUserVerified,
		aaguid: AAGUID{0x6b, 0x65, 0x79, 0x62, 0x6c, 0x61, 0x64, 0x65, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x01}}
	label := string(algorithm.String()) + "/" + format
	switch algorithm {
	case cose.AlgorithmES256:
		a.signer = fixedP256(t, label)
	case cose.AlgorithmEdDSA:
		a.signer = fixedEd25519(label)
	default:
		t.Fatalf("soft authenticator does not implement %v", algorithm)
	}
	id := sha256.Sum256([]byte("credential " + label))
	a.credentialID = id[:]
	if format == "packed" || format == "fido-u2f" {
		a.attestation = newTestAttestation(t, a.aaguid, nil)
	}
	return a
}

// certificateTweak edits the attestation leaf template before issuance.
type certificateTweak func(*x509.Certificate)

func newTestAttestation(t testing.TB, aaguid AAGUID, tweak certificateTweak) *testAttestation {
	t.Helper()
	return newTestAttestationCA(t, "attestation CA", aaguid, tweak)
}

// newTestAttestationCA issues an attestation leaf under the CA named label.
func newTestAttestationCA(t testing.TB, label string, aaguid AAGUID, tweak certificateTweak) *testAttestation {
	t.Helper()
	caKey := fixedP256(t, label)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Keyblade Test Attestation Root", Organization: []string{"Keyblade Test"}},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey := fixedP256(t, "attestation leaf")
	extension, _ := asn1.Marshal(aaguid[:])
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject:   pkix.Name{Country: []string{"US"}, Organization: []string{"Keyblade Test"}, OrganizationalUnit: []string{"Authenticator Attestation"}, CommonName: "Keyblade Test Authenticator"},
		NotBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true, ExtraExtensions: []pkix.Extension{{Id: idFIDOGenCEAAGUID, Value: extension}}}
	if tweak != nil {
		tweak(leaf)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &testAttestation{key: leafKey, chain: [][]byte{leafDER}, root: roots}
}

func (a *softAuthenticator) coseKey(t testing.TB) []byte {
	t.Helper()
	var fields map[int]any
	switch key := a.signer.Public().(type) {
	case *ecdsa.PublicKey:
		point, _ := key.Bytes()
		fields = map[int]any{coseKty: ktyEC2, coseAlg: int(a.algorithm), coseCrv: crvP256, coseX: point[1:33], coseY: point[33:]}
	case ed25519.PublicKey:
		fields = map[int]any{coseKty: ktyOKP, coseAlg: int(a.algorithm), coseCrv: crvEd25519, coseX: []byte(key)}
	}
	encoded, err := cbor.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (a *softAuthenticator) sign(t testing.TB, message []byte) []byte {
	t.Helper()
	switch key := a.signer.(type) {
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(message)
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return signature
	case ed25519.PrivateKey:
		return ed25519.Sign(key, message)
	}
	t.Fatal("unknown signer")
	return nil
}

// tweak edits a response at each stage of its construction.
type tweak struct {
	clientData func(map[string]any)                 // before serialization
	rawClient  func([]byte) []byte                  // after serialization, before hashing
	authData   func([]byte) []byte                  // before signing
	statement  func(t testing.TB, m map[string]any) // after signing (registration)
	signature  func([]byte) []byte                  // after signing (authentication)
	response   func(map[string]any)                 // final JSON object
	rpID       string                               // overrides the RP ID hashed into authData
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func clientDataJSON(t testing.TB, typ string, challenge []byte, origin string, edit func(map[string]any)) []byte {
	t.Helper()
	m := map[string]any{"type": typ, "challenge": b64(challenge), "origin": origin, "crossOrigin": false}
	if edit != nil {
		edit(m)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (a *softAuthenticator) authData(rpID string, attested []byte) []byte {
	hash := sha256.Sum256([]byte(rpID))
	data := append([]byte(nil), hash[:]...)
	flags := a.flags
	if attested != nil {
		flags |= FlagAttestedCredentialData
	}
	data = append(data, byte(flags))
	data = binary.BigEndian.AppendUint32(data, a.count)
	return append(data, attested...)
}

// register answers creation options the way a browser and authenticator
// would, returning RegistrationResponseJSON.
func (a *softAuthenticator) register(t testing.TB, options *RegistrationOptions, origin string, tw tweak) []byte {
	t.Helper()
	pk := options.Options.PublicKey
	a.userHandle = append([]byte(nil), pk.User.ID...)
	client := clientDataJSON(t, "webauthn.create", pk.Challenge, origin, tw.clientData)
	if tw.rawClient != nil {
		client = tw.rawClient(client)
	}
	clientHash := sha256.Sum256(client)
	coseKey := a.coseKey(t)
	attested := append(append([]byte(nil), a.aaguid[:]...), byte(len(a.credentialID)>>8), byte(len(a.credentialID)))
	attested = append(append(attested, a.credentialID...), coseKey...)
	rpID := pk.RP.ID
	if tw.rpID != "" {
		rpID = tw.rpID
	}
	data := a.authData(rpID, attested)
	if tw.authData != nil {
		data = tw.authData(data)
	}
	signed := append(append([]byte(nil), data...), clientHash[:]...)
	statement := map[string]any{}
	format := a.format
	switch a.format {
	case "packed-self":
		format = "packed"
		statement["alg"] = int(a.algorithm)
		statement["sig"] = a.sign(t, signed)
	case "packed":
		digest := sha256.Sum256(signed)
		signature, err := ecdsa.SignASN1(rand.Reader, a.attestation.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		statement["alg"] = int(cose.AlgorithmES256)
		statement["sig"] = signature
		statement["x5c"] = a.attestation.chain
	case "fido-u2f":
		key := a.signer.Public().(*ecdsa.PublicKey)
		point, _ := key.Bytes()
		message := append([]byte{0}, data[:32]...)
		message = append(append(append(message, clientHash[:]...), a.credentialID...), point...)
		digest := sha256.Sum256(message)
		signature, err := ecdsa.SignASN1(rand.Reader, a.attestation.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		statement["sig"] = signature
		statement["x5c"] = a.attestation.chain
	}
	if tw.statement != nil {
		tw.statement(t, statement)
		if f, ok := statement["$fmt"].(string); ok {
			format = f
			delete(statement, "$fmt")
		}
	}
	object, err := cbor.Marshal(map[string]any{"fmt": format, "attStmt": statement, "authData": data})
	if err != nil {
		t.Fatal(err)
	}
	response := map[string]any{
		"id": b64(a.credentialID), "rawId": b64(a.credentialID), "type": "public-key",
		"clientExtensionResults":  map[string]any{"credProps": map[string]any{"rk": true}},
		"authenticatorAttachment": "cross-platform",
		"response": map[string]any{"clientDataJSON": b64(client), "attestationObject": b64(object),
			"authenticatorData": b64(data), "transports": []string{"usb", "nfc"}, "publicKeyAlgorithm": int(a.algorithm)},
	}
	if tw.response != nil {
		tw.response(response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// login answers request options, returning AuthenticationResponseJSON. The
// counter advances by one first, as a hardware authenticator's would.
func (a *softAuthenticator) login(t testing.TB, options *LoginOptions, origin string, tw tweak) []byte {
	t.Helper()
	pk := options.Options.PublicKey
	a.count++
	client := clientDataJSON(t, "webauthn.get", pk.Challenge, origin, tw.clientData)
	if tw.rawClient != nil {
		client = tw.rawClient(client)
	}
	clientHash := sha256.Sum256(client)
	rpID := pk.RPID
	if tw.rpID != "" {
		rpID = tw.rpID
	}
	data := a.authData(rpID, nil)
	if tw.authData != nil {
		data = tw.authData(data)
	}
	signature := a.sign(t, append(append([]byte(nil), data...), clientHash[:]...))
	if tw.signature != nil {
		signature = tw.signature(signature)
	}
	response := map[string]any{
		"id": b64(a.credentialID), "rawId": b64(a.credentialID), "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64(client), "authenticatorData": b64(data), "signature": b64(signature), "userHandle": b64(a.userHandle)},
	}
	if tw.response != nil {
		tw.response(response)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// testClock is an adjustable clock for expiry tests.
type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

const (
	testRPID    = "login.example.com"
	testOrigin  = "https://login.example.com"
	testBinding = "session-0123456789abcdef"
)

// newTestRP returns a relying party for testRPID with a memory store.
func newTestRP(t testing.TB, edit func(*Config)) (*RelyingParty, *MemoryChallengeStore) {
	t.Helper()
	store, err := NewMemoryChallengeStore(1000)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{ID: testRPID, Name: "Example", Store: store}
	if edit != nil {
		edit(&config)
	}
	rp, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return rp, store
}

func beginRegistration(t testing.TB, rp *RelyingParty, user []byte) *RegistrationOptions {
	t.Helper()
	options, err := rp.BeginRegistration(context.Background(), RegistrationRequest{Binding: testBinding,
		User: UserEntity{ID: user, Name: "alice@example.com", DisplayName: "Alice"}, Extensions: &ExtensionInputs{CredProps: true}})
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func beginLogin(t testing.TB, rp *RelyingParty, user []byte, allow ...Credential) *LoginOptions {
	t.Helper()
	request := LoginRequest{Binding: testBinding, UserHandle: user}
	for _, c := range allow {
		request.AllowCredentials = append(request.AllowCredentials, c.Descriptor())
	}
	options, err := rp.BeginLogin(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return options
}

// lookupFor returns a CredentialLookup over the given records.
func lookupFor(records ...Credential) CredentialLookup {
	return func(_ context.Context, id, _ []byte) (*Credential, error) {
		for _, r := range records {
			if string(r.ID) == string(id) {
				c := r.Clone()
				return &c, nil
			}
		}
		return nil, ErrCredential
	}
}

// COSE_Key labels and values for hand-built test keys (RFC 9052 §7,
// RFC 9053 §7).
const (
	coseKty    = 1
	coseAlg    = 3
	coseCrv    = -1
	coseX      = -2
	coseY      = -3
	ktyOKP     = 1
	ktyEC2     = 2
	crvP256    = 1
	crvEd25519 = 6
)
