package tls

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// VerifyOptions are the certificate verification options.
type VerifyOptions struct {
	// CommonName is the expected certificate common name.
	CommonName string

	// Keys is the set of public keys that are allowed to sign the certificate.
	Keys map[signature.PublicKey]bool

	// AllowUnknownKeys specifies whether any key will be allowed iff Keys is nil.
	AllowUnknownKeys bool

	// AllowNoCertificate specifies whether connections presenting no certificates will be allowed.
	AllowNoCertificate bool
}

// VerifyCertificate verifies a TLS certificate as required by Oasis Core. Instead of using CAs,
// public key pinning is used and certificates must follow the template.
func VerifyCertificate(rawCerts [][]byte, opts VerifyOptions) error {
	// Allowing no certificate is useful in case access control is performed by a higher layer.
	if len(rawCerts) == 0 && opts.AllowNoCertificate {
		return nil
	}

	// Make sure there is only a single certificate.
	if len(rawCerts) != 1 {
		return fmt.Errorf("tls: expecting a single certificate (got: %d)", len(rawCerts))
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("tls: bad X509 certificate: %w", err)
	}

	// Public key should match the pinned key.
	if cert.PublicKeyAlgorithm != x509.Ed25519 || cert.SignatureAlgorithm != x509.PureEd25519 {
		return fmt.Errorf("tls: bad public key algorithm (expected: Ed25519)")
	}
	pk, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		// This should never happen due to the above check.
		return fmt.Errorf("tls: bad public key type (expected: Ed25519 got: %T)", cert.PublicKey)
	}
	if !opts.AllowUnknownKeys || opts.Keys != nil {
		var spk signature.PublicKey
		if err = spk.UnmarshalBinary(pk[:]); err != nil {
			// This should NEVER happen.
			return fmt.Errorf("tls: bad public key: %w", err)
		}
		if !opts.Keys[spk] {
			return fmt.Errorf("tls: bad public key (%s)", spk)
		}
	}

	// Common name should match.
	if cert.Subject.CommonName != opts.CommonName {
		return fmt.Errorf("tls: bad common name (expected: %s got: %s)",
			opts.CommonName,
			cert.Subject.CommonName,
		)
	}

	// Certificate serial number should match the template.
	if cert.SerialNumber.Cmp(certTemplate.SerialNumber) != 0 {
		return fmt.Errorf("tls: bad serial number (expected: %s got: %s)",
			certTemplate.SerialNumber,
			cert.SerialNumber,
		)
	}

	// Certificate key usage should match the template.
	if cert.KeyUsage != certTemplate.KeyUsage {
		return fmt.Errorf("tls: bad key usage (expected: %d got: %d)",
			certTemplate.KeyUsage,
			cert.KeyUsage,
		)
	}

	// Certificate extended key usage should match the template.
	if len(cert.ExtKeyUsage) != len(certTemplate.ExtKeyUsage) || len(cert.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("tls: bad extended key usage")
	}
	for i, eku := range certTemplate.ExtKeyUsage {
		if eku != cert.ExtKeyUsage[i] {
			return fmt.Errorf("tls: bad extended key usage (expected: %d got: %d)",
				eku,
				cert.ExtKeyUsage[i],
			)
		}
	}

	// There should be no extra extensions.
	if len(cert.ExtraExtensions) != 0 || len(cert.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("tls: bad extensions")
	}

	// Certificate should not be expired.
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("tls: current time %s is before %s", now.Format(time.RFC3339), cert.NotBefore.Format(time.RFC3339))
	} else if now.After(cert.NotAfter) {
		return fmt.Errorf("tls: current time %s is after %s", now.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}

	// Signature should be valid.
	if err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("tls: bad signature: %w", err)
	}

	return nil
}
