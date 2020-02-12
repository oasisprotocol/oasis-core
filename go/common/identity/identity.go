// Package identity encapsulates the node identity.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"path/filepath"
	"sync"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	tlsCert "github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/errors"
)

const (
	// NodeKeyPubFilename is the filename of the PEM encoded node public key.
	NodeKeyPubFilename = "identity_pub.pem"

	// P2PKeyPubFilename is the filename of the PEM encoded p2p public key.
	P2PKeyPubFilename = "p2p_pub.pem"

	// ConsensusKeyPubFilename is the filename of the PEM encoded consensus
	// public key.
	ConsensusKeyPubFilename = "consensus_pub.pem"

	// CommonName is the CommonName to use when generating TLS certificates.
	CommonName = "oasis-node"

	tlsKeyFilename  = "tls_identity.pem"
	tlsCertFilename = "tls_identity_cert.pem"
)

// ErrCertificateRotationForbidden is returned by RotateCertificates if
// TLS certificate rotation is forbidden.  This happens when rotation is
// enabled and an existing TLS certificate was successfully loaded
// (or a new one was generated and persisted to disk).
var ErrCertificateRotationForbidden = errors.New("identity", 1, "identity: TLS certificate rotation forbidden")

// Identity is a node identity.
type Identity struct {
	sync.RWMutex

	// NodeSigner is a node identity key signer.
	NodeSigner signature.Signer
	// P2PSigner is a node P2P link key signer.
	P2PSigner signature.Signer
	// ConsensusSigner is a node consensus key signer.
	ConsensusSigner signature.Signer
	// tlsSigner is a node TLS certificate signer.
	tlsSigner signature.Signer
	// tlsCertificate is a certificate that can be used for TLS.
	tlsCertificate *tls.Certificate
	// nextTLSCertificate is a certificate that can be used for TLS in the next rotation.
	nextTLSCertificate *tls.Certificate
	// DoNotRotateTLS flag is true if we mustn't rotate the TLS certificates.
	DoNotRotateTLS bool
}

// RotateCertificates rotates the identity's TLS certificates.
// This is called from worker/registration/worker.go every
// CfgRegistrationRotateCerts epochs (if it's non-zero).
func (i *Identity) RotateCertificates() error {
	if i.DoNotRotateTLS {
		// If we loaded an existing certificate or persisted a generated one
		// to disk, certificate rotation must be disabled.
		// This behaviour is required for sentry nodes to work.
		return ErrCertificateRotationForbidden
	}

	i.Lock()
	defer i.Unlock()

	if i.tlsCertificate != nil {
		// Use the prepared certificate.
		if i.nextTLSCertificate != nil {
			i.tlsCertificate = i.nextTLSCertificate
			i.tlsSigner = memory.NewFromRuntime(i.tlsCertificate.PrivateKey.(ed25519.PrivateKey))
		}

		// Generate a new TLS certificate to be used in the next rotation.
		var err error
		i.nextTLSCertificate, err = tlsCert.Generate(CommonName)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetTLSSigner returns the current TLS signer.
func (i *Identity) GetTLSSigner() signature.Signer {
	i.RLock()
	defer i.RUnlock()

	return i.tlsSigner
}

// SetTLSSigner sets the current TLS signer.
func (i *Identity) SetTLSSigner(s signature.Signer) {
	i.Lock()
	defer i.Unlock()

	i.tlsSigner = s
}

// GetTLSCertificate returns the current TLS certificate.
func (i *Identity) GetTLSCertificate() *tls.Certificate {
	i.RLock()
	defer i.RUnlock()

	return i.tlsCertificate
}

// SetTLSCertificate sets the current TLS certificate.
func (i *Identity) SetTLSCertificate(cert *tls.Certificate) {
	i.Lock()
	defer i.Unlock()

	i.tlsCertificate = cert
}

// GetNextTLSCertificate returns the next TLS certificate.
func (i *Identity) GetNextTLSCertificate() *tls.Certificate {
	i.RLock()
	defer i.RUnlock()

	return i.nextTLSCertificate
}

// SetNextTLSCertificate sets the next TLS certificate.
func (i *Identity) SetNextTLSCertificate(nextCert *tls.Certificate) {
	i.Lock()
	defer i.Unlock()

	i.nextTLSCertificate = nextCert
}

// Load loads an identity.
func Load(dataDir string, signerFactory signature.SignerFactory) (*Identity, error) {
	return doLoadOrGenerate(dataDir, signerFactory, false, false)
}

// LoadOrGenerate loads or generates an identity.
// If persistTLS is true, it saves the generated TLS certificates to disk.
func LoadOrGenerate(dataDir string, signerFactory signature.SignerFactory, persistTLS bool) (*Identity, error) {
	return doLoadOrGenerate(dataDir, signerFactory, true, persistTLS)
}

func doLoadOrGenerate(dataDir string, signerFactory signature.SignerFactory, shouldGenerate bool, persistTLS bool) (*Identity, error) {
	var signers []signature.Signer
	for _, v := range []struct {
		role  signature.SignerRole
		pubFn string
	}{
		{signature.SignerNode, NodeKeyPubFilename},
		{signature.SignerP2P, P2PKeyPubFilename},
		{signature.SignerConsensus, ConsensusKeyPubFilename},
	} {
		signer, err := signerFactory.Load(v.role)
		switch err {
		case nil:
		case signature.ErrNotExist:
			if !shouldGenerate {
				return nil, err
			}
			if signer, err = signerFactory.Generate(v.role, rand.Reader); err != nil {
				return nil, err
			}
		default:
			return nil, err
		}

		var checkPub signature.PublicKey
		if err = checkPub.LoadPEM(filepath.Join(dataDir, v.pubFn), signer); err != nil {
			return nil, err
		}

		signers = append(signers, signer)
	}

	var (
		nextCert *tls.Certificate
		dnr      bool
	)

	// First, check if we can load the TLS certificate from disk.
	tlsCertPath, tlsKeyPath := TLSCertPaths(dataDir)
	cert, err := tlsCert.Load(tlsCertPath, tlsKeyPath)
	if err == nil {
		// Load successful, ensure that we won't ever rotate the certificates.
		dnr = true
	} else {
		// Freshly generate TLS certificates.
		cert, err = tlsCert.Generate(CommonName)
		if err != nil {
			return nil, err
		}

		if persistTLS {
			// Save generated TLS certificate to disk.
			err = tlsCert.Save(tlsCertPath, tlsKeyPath, cert)
			if err != nil {
				return nil, err
			}

			// Disable TLS rotation if we're persisting TLS certificates.
			dnr = true
		} else {
			// Not persisting TLS certificate to disk, generate a new
			// certificate to be used in the next rotation.
			nextCert, err = tlsCert.Generate(CommonName)
			if err != nil {
				return nil, err
			}
		}
	}

	return &Identity{
		NodeSigner:         signers[0],
		P2PSigner:          signers[1],
		ConsensusSigner:    signers[2],
		tlsSigner:          memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey)),
		tlsCertificate:     cert,
		nextTLSCertificate: nextCert,
		DoNotRotateTLS:     dnr,
	}, nil
}

// TLSCertPaths returns the TLS private key and certificate paths relative
// to the passed data directory.
func TLSCertPaths(dataDir string) (string, string) {
	var (
		tlsKeyPath  = filepath.Join(dataDir, tlsKeyFilename)
		tlsCertPath = filepath.Join(dataDir, tlsCertFilename)
	)

	return tlsCertPath, tlsKeyPath
}
