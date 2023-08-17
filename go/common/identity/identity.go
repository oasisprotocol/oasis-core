// Package identity encapsulates the node identity.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	tlsCert "github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
)

const (
	// NodeKeyPubFilename is the filename of the PEM encoded node public key.
	NodeKeyPubFilename = "identity_pub.pem"

	// P2PKeyPubFilename is the filename of the PEM encoded p2p public key.
	P2PKeyPubFilename = "p2p_pub.pem"

	// ConsensusKeyPubFilename is the filename of the PEM encoded consensus
	// public key.
	ConsensusKeyPubFilename = "consensus_pub.pem"

	// VRFKeyPubFilename is the filename of the PEM encoded node VRF public key.
	VRFKeyPubFilename = "vrf_pub.pem"

	// CommonName is the CommonName to use when generating TLS certificates.
	CommonName = "oasis-node"

	tlsKeyFilename  = "tls_identity.pem"
	tlsCertFilename = "tls_identity_cert.pem"

	tlsEphemeralKeyBaseFilename = "tls_ephemeral"

	tlsEphemeralGenCurrent     = ""
	tlsEphemeralGenNext        = "_next"
	tlsEphemeralGenRotationNew = "_new_next"

	// These are used for the sentry client connection to the sentry node and are never rotated.
	tlsSentryClientKeyFilename  = "sentry_client_tls_identity.pem"
	tlsSentryClientCertFilename = "sentry_client_tls_identity_cert.pem"
)

// RequiredSignerRoles is the required signer roles needed to load or
// provision a node identity.
var RequiredSignerRoles = []signature.SignerRole{
	signature.SignerNode,
	signature.SignerP2P,
	signature.SignerConsensus,
	signature.SignerVRF,
}

// Identity is a node identity.
type Identity struct {
	// NodeSigner is a node identity key signer.
	NodeSigner signature.Signer
	// P2PSigner is a node P2P link key signer.
	P2PSigner signature.Signer
	// ConsensusSigner is a node consensus key signer.
	ConsensusSigner signature.Signer
	// VRFSigner is a node VRF key signer.
	VRFSigner signature.Signer

	// TLSSentryClientCertificate is the client certificate used for
	// connecting to the sentry node's control connection.  It is never rotated.
	TLSSentryClientCertificate *tls.Certificate

	// TLSSigner is a node TLS certificate signer.
	TLSSigner signature.Signer
	// TLSCertificate is a certificate that can be used for TLS.
	TLSCertificate *tls.Certificate
}

// WithTLSCertificate creates a new identity with the specified TLS certificate,
// but otherwise leaves it blank.
func WithTLSCertificate(cert *tls.Certificate) *Identity {
	return &Identity{
		TLSSigner:      memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey)),
		TLSCertificate: cert,
	}
}

// Load loads an identity.
func Load(dataDir string, signerFactory signature.SignerFactory) (*Identity, error) {
	return doLoadOrGenerate(dataDir, signerFactory, false)
}

// LoadOrGenerate loads or generates an identity.
func LoadOrGenerate(dataDir string, signerFactory signature.SignerFactory) (*Identity, error) {
	return doLoadOrGenerate(dataDir, signerFactory, true)
}

func doLoadOrGenerate(dataDir string, signerFactory signature.SignerFactory, shouldGenerate bool) (*Identity, error) {
	// Remove ephemeral TLS keys in case they exist.
	// TODO: the constants, ephemeralKeyPath() and this code should be removed after the next release.
	for _, gen := range []string{
		tlsEphemeralGenCurrent,
		tlsEphemeralGenNext,
		tlsEphemeralGenRotationNew,
	} {
		path := ephemeralKeyPath(dataDir, gen)
		_ = os.Remove(path)
	}

	var signers []signature.Signer
	for _, v := range []struct {
		role  signature.SignerRole
		pubFn string
	}{
		{signature.SignerNode, NodeKeyPubFilename},
		{signature.SignerP2P, P2PKeyPubFilename},
		{signature.SignerConsensus, ConsensusKeyPubFilename},
		{signature.SignerVRF, VRFKeyPubFilename},
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

	// Load and re-generate node's persistent TLS certificate (if it exists).
	// NOTE: This will reuse the node's persistent TLS private key (if it
	// exists) and re-generate the TLS certificate with a validity of 1 year.
	// NOTE: The node needs to be restarted at least once a year so the TLS
	// certificate doesn't expire.
	tlsCertPath, tlsKeyPath := TLSCertPaths(dataDir)
	cert, err := tlsCert.LoadFromKey(tlsKeyPath, CommonName)
	if err != nil {
		// Loading node's persistent TLS private key failed, generate a new
		// private key and the corresponding TLS certificate.
		cert, err = tlsCert.Generate(CommonName)
		if err != nil {
			return nil, err
		}
	}

	// Save re-generated TLS certificate (and private key) to disk.
	err = tlsCert.Save(tlsCertPath, tlsKeyPath, cert)
	if err != nil {
		return nil, err
	}

	// Load and re-generate the sentry client TLS certificate for this node (if
	// it exists).
	// NOTE: This will reuse the sentry client's private key (if it exists)
	// and re-generate the TLS certificate with a validity of 1 year.
	// NOTE: The node needs to be restarted at least once a year so the TLS
	// certificate doesn't expire.
	tlsSentryClientCertPath, tlsSentryClientKeyPath := TLSSentryClientCertPaths(dataDir)
	sentryClientCert, err := tlsCert.LoadFromKey(tlsSentryClientKeyPath, CommonName)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("identity: unable to read sentry client key from file: %w", err)
		}
		// Loading sentry client's private key failed, generate a new
		// private key and the corresponding TLS certificate.
		sentryClientCert, err = tlsCert.Generate(CommonName)
		if err != nil {
			return nil, err
		}
	}
	// Save the re-generated TLS certificate (and private key) to disk.
	err = tlsCert.Save(tlsSentryClientCertPath, tlsSentryClientKeyPath, sentryClientCert)
	if err != nil {
		return nil, err
	}

	return &Identity{
		NodeSigner:                 signers[0],
		P2PSigner:                  signers[1],
		ConsensusSigner:            signers[2],
		VRFSigner:                  signers[3],
		TLSSigner:                  memory.NewFromRuntime(cert.PrivateKey.(ed25519.PrivateKey)),
		TLSCertificate:             cert,
		TLSSentryClientCertificate: sentryClientCert,
	}, nil
}

func ephemeralKeyPath(dataDir, generation string) string {
	return filepath.Join(dataDir, fmt.Sprintf("%s%s.pem", tlsEphemeralKeyBaseFilename, generation))
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

// TLSSentryClientCertPaths returns the sentry client TLS private key and
// certificate paths relative to the passed data directory.
func TLSSentryClientCertPaths(dataDir string) (string, string) {
	var (
		tlsKeyPath  = filepath.Join(dataDir, tlsSentryClientKeyFilename)
		tlsCertPath = filepath.Join(dataDir, tlsSentryClientCertFilename)
	)

	return tlsCertPath, tlsKeyPath
}
