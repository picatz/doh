package serve

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/picatz/doh/internal/api"
	"github.com/picatz/doh/internal/cms"
)

// acmeSigningWait bounds how long signing a configuration profile waits
// for an ACME certificate, which may still be being obtained; past it, the
// profile is served unsigned.
const acmeSigningWait = 10 * time.Second

// Notes for people about how a configuration profile is signed.
const (
	noteUnsigned  = "This server doesn't sign its configuration profiles, so devices show them as Unverified. They install and work the same."
	noteUntrusted = "The signing certificate doesn't chain to a root this server trusts (it may be self-signed, or from a private authority), so devices show the profile as Unverified unless they trust that root. It installs and works the same."
)

// profileSigner signs Apple configuration profiles, so devices show them
// as verified when the certificate chains to a root they trust.
type profileSigner struct {
	// source names where the certificate comes from, for logs.
	source string

	// certificate returns the current certificate and key.
	certificate func() (*tls.Certificate, error)

	logger *slog.Logger
	now    func() time.Time

	// roots are the roots trust is judged by; nil means the system's.
	roots *x509.CertPool

	// warned records the serial numbers of expired certificates already
	// logged, so each is logged once.
	warned sync.Map
}

// configureProfileSigning chooses the certificate configuration profiles
// are signed with: the profile signing files, else the TLS certificate
// files, else the ACME certificate for the hostname, else none.
func (s *Server) configureProfileSigning() error {
	p := &profileSigner{logger: s.logger, now: time.Now}
	switch ps := s.config.TLS.ProfileSigning; {
	case ps.CertFile != "":
		// Load once here for a clear error at startup: a certificate and
		// key that don't match, or a key that can't sign profiles.
		cert, err := tls.LoadX509KeyPair(ps.CertFile, ps.KeyFile)
		if err != nil {
			return fmt.Errorf("serve: profile signing certificate %s and key %s: %w", ps.CertFile, ps.KeyFile, err)
		}
		if err := p.check(&cert); err != nil {
			return fmt.Errorf("serve: profile signing certificate %s: %w", ps.CertFile, err)
		}
		reloader, err := newCertReloader(ps.CertFile, ps.KeyFile, s.logger)
		if err != nil {
			return err
		}
		p.source, p.certificate = "profile signing files", func() (*tls.Certificate, error) { return reloader.GetCertificate(nil) }

	case s.reloader != nil:
		cert, _ := s.reloader.GetCertificate(nil)
		if err := p.check(cert); err != nil {
			s.logger.Warn("configuration profiles won't be signed: the TLS certificate can't sign them; set --profile-signing-cert and --profile-signing-key to sign them with another",
				slog.Any("error", err))
			return nil
		}
		p.source, p.certificate = "TLS certificate", func() (*tls.Certificate, error) { return s.reloader.GetCertificate(nil) }

	case s.acme != nil && s.config.Hostname != "":
		p.source, p.certificate = "ACME certificate", s.acmeSigningCertificate

	default:
		s.logger.Info("configuration profiles won't be signed, so Apple devices show them as unverified: the server has no certificate (set --profile-signing-cert and --profile-signing-key to sign them)")
		return nil
	}
	s.profileSigner = p
	return nil
}

// acmeSigningCertificate returns the ECDSA ACME certificate for the
// server's hostname, waiting at most acmeSigningWait for it.
func (s *Server) acmeSigningCertificate() (*tls.Certificate, error) {
	hello := &tls.ClientHelloInfo{
		ServerName:       s.config.Hostname,
		SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:  []tls.CurveID{tls.CurveP256},
		CipherSuites:     []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
	type result struct {
		cert *tls.Certificate
		err  error
	}
	done := make(chan result, 1)
	go func() {
		cert, err := s.acme.GetCertificate(hello)
		done <- result{cert, err}
	}()
	select {
	case r := <-done:
		return r.cert, r.err
	case <-time.After(acmeSigningWait):
		return nil, errors.New("the ACME certificate isn't ready yet")
	}
}

// check reports whether cert can sign configuration profiles, logging a
// warning if it isn't valid now.
func (p *profileSigner) check(cert *tls.Certificate) error {
	leaf, err := leafOf(cert)
	if err != nil {
		return err
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("its private key can't sign")
	}
	switch signer.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
	default:
		return fmt.Errorf("its %T key can't sign configuration profiles: use an ECDSA or RSA key", signer.Public())
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("its key usage doesn't allow digital signatures")
	}
	p.warnValidity(leaf)
	return nil
}

// warnValidity logs a warning, once per certificate, if leaf isn't valid
// now: devices show profiles it signs as unverified.
func (p *profileSigner) warnValidity(leaf *x509.Certificate) {
	now := p.now()
	if !now.After(leaf.NotAfter) && !now.Before(leaf.NotBefore) {
		return
	}
	if _, warned := p.warned.LoadOrStore(leaf.SerialNumber.String(), true); warned {
		return
	}
	p.logger.Warn("the configuration profile signing certificate isn't valid now, so devices show the profiles it signs as unverified",
		slog.String("subject", leaf.Subject.String()),
		slog.Time("not_before", leaf.NotBefore), slog.Time("not_after", leaf.NotAfter))
}

// leafOf returns cert's leaf certificate, parsing it if need be.
func leafOf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("no certificate")
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return leaf, nil
}

// chainOf returns cert's chain, parsed, leaf first.
func chainOf(cert *tls.Certificate) ([]*x509.Certificate, error) {
	leaf, err := leafOf(cert)
	if err != nil {
		return nil, err
	}
	chain := []*x509.Certificate{leaf}
	for _, der := range cert.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate chain: %w", err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

// sign returns content signed, or false if it can't be, logging why.
func (p *profileSigner) sign(content []byte) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	cert, err := p.certificate()
	var chain []*x509.Certificate
	if err == nil {
		chain, err = chainOf(cert)
	}
	if err != nil {
		p.logger.Warn("serving the configuration profile unsigned", slog.String("certificate", p.source), slog.Any("error", err))
		return nil, false
	}
	p.warnValidity(chain[0])
	signer, _ := cert.PrivateKey.(crypto.Signer)
	signed, err := cms.Sign(content, cms.Signer{Chain: chain, Key: signer}, p.now())
	if err != nil {
		p.logger.Warn("serving the configuration profile unsigned", slog.String("certificate", p.source), slog.Any("error", err))
		return nil, false
	}
	return signed, true
}

// status describes how configuration profiles are signed now.
func (p *profileSigner) status() *api.ProfileSigning {
	if p == nil {
		return &api.ProfileSigning{Note: noteUnsigned}
	}
	cert, err := p.certificate()
	var chain []*x509.Certificate
	if err == nil {
		chain, err = chainOf(cert)
	}
	if err != nil {
		return &api.ProfileSigning{Note: "The signing certificate isn't available (" + err.Error() + "), so configuration profiles are served unsigned for now, and devices show them as Unverified."}
	}

	leaf := chain[0]
	expires := leaf.NotAfter
	st := &api.ProfileSigning{Signed: true, Signer: leaf.Subject.CommonName, Expires: &expires}
	if st.Signer == "" && len(leaf.DNSNames) > 0 {
		st.Signer = leaf.DNSNames[0]
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	now := p.now()
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         p.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	st.Trusted = err == nil
	switch {
	case now.After(leaf.NotAfter):
		st.Note = "The signing certificate expired on " + leaf.NotAfter.UTC().Format(time.DateOnly) + ", so devices show the profile as Unverified until it's renewed. It installs and works the same."
	case now.Before(leaf.NotBefore):
		st.Note = "The signing certificate isn't valid until " + leaf.NotBefore.UTC().Format(time.DateOnly) + ", so devices show the profile as Unverified until then. It installs and works the same."
	case !st.Trusted:
		st.Note = noteUntrusted
	}
	return st
}
