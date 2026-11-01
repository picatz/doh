package webauthn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/picatz/cbor"

	"github.com/picatz/doh/internal/cose"
)

// Attestation statement format identifiers.
// https://www.iana.org/assignments/webauthn/webauthn.xhtml
const (
	FormatNone             = "none"
	FormatPacked           = "packed"
	FormatFIDOU2F          = "fido-u2f"
	FormatTPM              = "tpm"
	FormatAndroidKey       = "android-key"
	FormatAndroidSafetyNet = "android-safetynet"
	FormatApple            = "apple"
	FormatCompound         = "compound"
)

// AttestationType is the attestation type a verified statement conveys.
// https://www.w3.org/TR/webauthn-3/#sctn-attestation-types
type AttestationType string

// Attestation types.
const (
	// AttestationTypeNone means no attestation: nothing is known about the
	// authenticator model.
	AttestationTypeNone AttestationType = "none"
	// AttestationTypeSelf means the credential key signed its own creation.
	// It proves possession of the key and nothing about the model.
	AttestationTypeSelf AttestationType = "self"
	// AttestationTypeBasic means an attestation certificate signed the
	// creation. Without metadata the relying party cannot tell Basic from
	// AttCA attestation, and the chain has not been checked against any root
	// unless [Policy.TrustAttestation] did so.
	AttestationTypeBasic AttestationType = "basic"
)

// AttestationObject is a decoded attestation object.
// https://www.w3.org/TR/webauthn-3/#sctn-attestation
type AttestationObject struct {
	Format string
	// AuthData is the raw authenticator data, exactly as signed.
	AuthData []byte
	// Statement holds the raw CBOR of each attestation statement member.
	Statement map[string][]byte
}

// Attestation is the outcome of a verified attestation statement.
type Attestation struct {
	Format string
	Type   AttestationType
	// AAGUID is copied from the attested credential data. It is bound to a
	// certificate only when Type is [AttestationTypeBasic] and the chain is
	// trusted. It is always zero for "fido-u2f", whose signature does not
	// cover the AAGUID (§8.6); [Credential.AAGUID] still records the
	// unattested claim.
	AAGUID AAGUID
	// Certificates is the attestation trust path (x5c) in DER, leaf first.
	// The leaf signed the creation; no chain has been validated here.
	Certificates [][]byte
}

// attestationOptions bounds attestation object decoding.
func attestationOptions() cbor.DecoderOptions {
	return cbor.DecoderOptions{MaxNestedLevels: 8, MaxArrayElements: 16, MaxMapPairs: 32,
		MaxStringBytes: 1024, MaxBytes: 64 << 10, MaxEncodedBytes: 256 << 10, RejectTags: true}
}

// ParseAttestationObject decodes an attestation object into its format,
// authenticator data and raw statement members. It checks the CBOR
// structure only; members other than fmt, authData and attStmt are ignored.
// Failures wrap [ErrMalformed].
func ParseAttestationObject(data []byte) (*AttestationObject, error) {
	var fields map[string]cbor.RawMessage
	if len(data) == 0 || data[0]>>5 != 5 || attestationOptions().Unmarshal(data, &fields) != nil {
		return nil, fmt.Errorf("%w: attestation object is not a bounded CBOR map", ErrMalformed)
	}
	out := &AttestationObject{Statement: map[string][]byte{}}
	var statement map[string]cbor.RawMessage
	options := attestationOptions()
	if raw, ok := fields["fmt"]; !ok || len(raw) == 0 || raw[0]>>5 != 3 || options.Unmarshal(raw, &out.Format) != nil {
		return nil, fmt.Errorf("%w: attestation object fmt must be a text string", ErrMalformed)
	}
	if raw, ok := fields["authData"]; !ok || len(raw) == 0 || raw[0]>>5 != 2 || options.Unmarshal(raw, &out.AuthData) != nil {
		return nil, fmt.Errorf("%w: attestation object authData must be a byte string", ErrMalformed)
	}
	if raw, ok := fields["attStmt"]; !ok || len(raw) == 0 || raw[0]>>5 != 5 || options.Unmarshal(raw, &statement) != nil {
		return nil, fmt.Errorf("%w: attestation object attStmt must be a map", ErrMalformed)
	}
	if len(out.Format) == 0 || len(out.Format) > 32 {
		return nil, fmt.Errorf("%w: attestation format identifier must be 1–32 bytes", ErrMalformed)
	}
	for name, raw := range statement {
		out.Statement[name] = []byte(raw)
	}
	return out, nil
}

// verifyStatement runs the verification procedure of the statement's format,
// given the parsed authenticator data (with attested credential data), the
// parsed credential key and the client data hash.
func verifyStatement(object *AttestationObject, auth *AuthenticatorData, credentialKey *PublicKey, clientDataHash []byte) (*Attestation, error) {
	result := &Attestation{Format: object.Format, AAGUID: auth.Attested.AAGUID}
	signed := append(bytes.Clone(object.AuthData), clientDataHash...)
	kind := CeremonyRegistration
	switch object.Format {
	case FormatNone:
		// §8.7: attStmt is an empty map.
		if len(object.Statement) != 0 {
			return nil, failure(kind, ErrMalformed, specNone, "none attestation statement is not empty")
		}
		result.Type = AttestationTypeNone
		return result, nil
	case FormatPacked:
		return verifyPacked(object, auth, credentialKey, signed, result)
	case FormatFIDOU2F:
		return verifyU2F(object, auth, credentialKey, clientDataHash, result)
	case FormatTPM, FormatAndroidKey, FormatAndroidSafetyNet, FormatApple, FormatCompound:
		return nil, failure(kind, ErrUnsupported, "https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats", "attestation format "+object.Format+" is not verified by this package yet")
	}
	return nil, failure(kind, ErrUnsupported, specRegistration, "unknown attestation statement format")
}

// verifyPacked implements the packed verification procedure (§8.2).
func verifyPacked(object *AttestationObject, auth *AuthenticatorData, credentialKey *PublicKey, signed []byte, result *Attestation) (*Attestation, error) {
	kind := CeremonyRegistration
	options := attestationOptions()
	var alg int64
	var signature []byte
	rawAlg, okAlg := object.Statement["alg"]
	rawSig, okSig := object.Statement["sig"]
	if !okAlg || !okSig || options.Unmarshal(rawAlg, &alg) != nil || len(rawSig) == 0 || rawSig[0]>>5 != 2 || options.Unmarshal(rawSig, &signature) != nil {
		return nil, failure(kind, ErrMalformed, specPacked, "packed statement needs integer alg and byte-string sig")
	}
	algorithm := cose.Algorithm(alg)
	rawChain, hasChain := object.Statement["x5c"]
	if len(object.Statement) != 2 && !(hasChain && len(object.Statement) == 3) {
		return nil, failure(kind, ErrMalformed, specPacked, "packed statement has unexpected members")
	}
	if !hasChain {
		// Self attestation: "Validate that alg matches the algorithm of the
		// credentialPublicKey in authenticatorData", then verify sig with it.
		if algorithm != credentialKey.Algorithm {
			return nil, failure(kind, ErrVerification, specPacked, "packed self attestation alg differs from the credential key")
		}
		if credentialKey.Verify(signed, signature) != nil {
			return nil, failure(kind, ErrVerification, specPacked, "packed self attestation signature is invalid")
		}
		result.Type = AttestationTypeSelf
		return result, nil
	}
	chain, leaf, err := parseChain(rawChain, 0)
	if err != nil {
		return nil, failure(kind, ErrMalformed, specPacked, "packed x5c is not a chain of DER certificates")
	}
	if algorithm.Available() != nil {
		return nil, failure(kind, ErrUnsupported, specPacked, "packed attestation algorithm "+algorithm.String()+" is not supported")
	}
	// "Verify that sig is a valid signature over the concatenation of
	// authenticatorData and clientDataHash using the attestation public key
	// in attestnCert with the algorithm specified in alg."
	if !verify(algorithm, leaf.PublicKey, signed, signature) {
		return nil, failure(kind, ErrVerification, specPacked, "packed attestation signature is invalid")
	}
	// "Verify that attestnCert meets the requirements in §8.2.1."
	if err := checkPackedCertificate(leaf, auth.Attested.AAGUID); err != nil {
		return nil, err
	}
	result.Type = AttestationTypeBasic
	result.Certificates = chain
	return result, nil
}

// idFIDOGenCEAAGUID is the AAGUID certificate extension of §8.2.1.
var idFIDOGenCEAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// checkPackedCertificate applies the packed attestation certificate
// requirements (§8.2.1) and the AAGUID extension check of §8.2.
func checkPackedCertificate(leaf *x509.Certificate, aaguid AAGUID) error {
	kind := CeremonyRegistration
	subject := leaf.Subject
	if leaf.Version != 3 {
		return failure(kind, ErrVerification, specPackedCert, "attestation certificate is not X.509 version 3")
	}
	if len(subject.Country) == 0 || len(subject.Organization) == 0 || subject.CommonName == "" ||
		len(subject.OrganizationalUnit) != 1 || subject.OrganizationalUnit[0] != "Authenticator Attestation" {
		return failure(kind, ErrVerification, specPackedCert, "attestation certificate subject lacks C, O, CN or OU \"Authenticator Attestation\"")
	}
	// "The Basic Constraints extension MUST have the CA component set to
	// false." The extension must be present, not merely CA-less by omission.
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return failure(kind, ErrVerification, specPackedCert, "attestation certificate lacks Basic Constraints with CA false")
	}
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(idFIDOGenCEAAGUID) {
			continue
		}
		var value []byte
		rest, err := asn1.Unmarshal(extension.Value, &value)
		if err != nil || len(rest) != 0 || extension.Critical || !bytes.Equal(value, aaguid[:]) {
			return failure(kind, ErrVerification, specPacked, "attestation certificate AAGUID extension is critical or differs from authenticator data")
		}
	}
	return nil
}

// verifyU2F implements the fido-u2f verification procedure (§8.6).
func verifyU2F(object *AttestationObject, auth *AuthenticatorData, credentialKey *PublicKey, clientDataHash []byte, result *Attestation) (*Attestation, error) {
	kind := CeremonyRegistration
	options := attestationOptions()
	var signature []byte
	rawSig, okSig := object.Statement["sig"]
	rawChain, okChain := object.Statement["x5c"]
	if !okSig || !okChain || len(object.Statement) != 2 || len(rawSig) == 0 || rawSig[0]>>5 != 2 || options.Unmarshal(rawSig, &signature) != nil {
		return nil, failure(kind, ErrMalformed, specU2F, "fido-u2f statement needs exactly sig and x5c")
	}
	// The U2F signature does not cover the AAGUID (U2F devices have none),
	// so the attestation must not vouch for whatever authData claims. It is
	// not rejected: the specification's own fido-u2f test vector carries a
	// nonzero AAGUID. [Attestation.AAGUID] is left zero instead.
	result.AAGUID = AAGUID{}
	// "Check that x5c has exactly one element ... If certificate public key
	// is not an Elliptic Curve (EC) public key over the P-256 curve,
	// terminate this algorithm and return an appropriate error."
	chain, leaf, err := parseChain(rawChain, 1)
	if err != nil {
		return nil, failure(kind, ErrMalformed, specU2F, "fido-u2f x5c must hold exactly one DER certificate")
	}
	certificateKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || certificateKey.Curve != elliptic.P256() {
		return nil, failure(kind, ErrVerification, specU2F, "fido-u2f attestation key is not ECDSA P-256")
	}
	// "Convert the COSE_KEY formatted credentialPublicKey to Raw ANSI X9.62
	// public key format": only an ES256 P-256 key has 32-byte x and y.
	ecKey, ok := credentialKey.Key.(*ecdsa.PublicKey)
	if !ok || credentialKey.Algorithm != cose.AlgorithmES256 || ecKey.Curve != elliptic.P256() {
		return nil, failure(kind, ErrVerification, specU2F, "fido-u2f credential key is not an ES256 P-256 key")
	}
	point, err := ecKey.Bytes()
	if err != nil || len(point) != 65 {
		return nil, failure(kind, ErrVerification, specU2F, "fido-u2f credential key cannot be encoded")
	}
	// verificationData = 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
	message := make([]byte, 0, 1+32+len(clientDataHash)+len(auth.Attested.CredentialID)+len(point))
	message = append(message, 0)
	message = append(message, auth.RPIDHash[:]...)
	message = append(message, clientDataHash...)
	message = append(message, auth.Attested.CredentialID...)
	message = append(message, point...)
	if !verify(cose.AlgorithmES256, certificateKey, message, signature) {
		return nil, failure(kind, ErrVerification, specU2F, "fido-u2f attestation signature is invalid")
	}
	result.Type = AttestationTypeBasic
	result.Certificates = chain
	return result, nil
}

// parseChain decodes an x5c array of DER certificates, leaf first. exactly,
// when nonzero, is the required length; otherwise 1–8 certificates are
// allowed. Every certificate must parse.
func parseChain(raw []byte, exactly int) ([][]byte, *x509.Certificate, error) {
	var chain [][]byte
	if len(raw) == 0 || raw[0]>>5 != 4 || attestationOptions().Unmarshal(raw, &chain) != nil {
		return nil, nil, ErrMalformed
	}
	if len(chain) == 0 || len(chain) > 8 || (exactly != 0 && len(chain) != exactly) {
		return nil, nil, ErrMalformed
	}
	var leaf *x509.Certificate
	for i, der := range chain {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, ErrMalformed
		}
		if i == 0 {
			leaf = certificate
		}
	}
	return chain, leaf, nil
}

// TrustRoots returns a [Policy.TrustAttestation] function that accepts only
// certificate-based attestation ([AttestationTypeBasic]) whose trust path
// chains to one of roots. Self and none attestation are rejected with
// [ErrVerification], since they say nothing about the model.
//
// Called by [RelyingParty.FinishRegistration], it checks validity at the
// relying party's [Config.Clock] time, which the context carries; called
// any other way, it uses time.Now.
//
// Use roots the application chose deliberately, such as a vendor's published
// attestation root or roots from verified FIDO metadata. This checks the
// chain only: it does not check revocation or metadata status reports.
func TrustRoots(roots *x509.CertPool) func(context.Context, Attestation) error {
	return func(ctx context.Context, attestation Attestation) error {
		now, ok := ctx.Value(verificationTimeKey{}).(time.Time)
		if !ok {
			now = time.Now()
		}
		return verifyChain(roots, attestation, now)
	}
}

// verificationTimeKey is the context key under which FinishRegistration
// passes its clock's time to the [Policy.TrustAttestation] callback.
type verificationTimeKey struct{}

func verifyChain(roots *x509.CertPool, attestation Attestation, now time.Time) error {
	kind := CeremonyRegistration
	if roots == nil || attestation.Type != AttestationTypeBasic || len(attestation.Certificates) == 0 {
		return failure(kind, ErrVerification, specRegistration, "attestation is not certified by a trusted root")
	}
	leaf, err := x509.ParseCertificate(attestation.Certificates[0])
	if err != nil {
		return failure(kind, ErrMalformed, specRegistration, "attestation certificate does not parse")
	}
	intermediates := x509.NewCertPool()
	for _, der := range attestation.Certificates[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return failure(kind, ErrMalformed, specRegistration, "attestation certificate does not parse")
		}
		intermediates.AddCert(certificate)
	}
	// Attestation certificates carry no TLS extended key usage.
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return failure(kind, ErrVerification, specRegistration, "attestation trust path does not chain to a trusted root")
	}
	return nil
}
