// Package identity encapsulates the node identity.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

const (
	// NodeKeyPubFilename is the filename of the PEM encoded node public key.
	NodeKeyPubFilename = "identity_pub.pem"

	// P2PKeyPubFilename is the filename of the PEM encoded p2p public key.
	P2PKeyPubFilename = "p2p_pub.pem"

	tlsKeyFilename  = "tls_identity.pem"
	tlsCertFilename = "tls_identity_cert.pem"
	tlsKeyPEMType   = "EC PRIVATE KEY"
	tlsCertPEMType  = "CERTIFICATE"
)

var tlsTemplate = x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		CommonName: "ekiden-node",
	},
	KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
	ExtKeyUsage: []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	},
}

// Identity is a node identity.
type Identity struct {
	// NodeSigner is a node identity key signer.
	NodeSigner signature.Signer
	// P2PSigner is a node P2P link key signer.
	P2PSigner signature.Signer
	// TLSKey is a private key used for TLS connections.
	TLSKey *ecdsa.PrivateKey
	// TLSCertificate is a certificate that can be used for TLS.
	TLSCertificate *tls.Certificate
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
	var signers []signature.Signer
	for _, v := range []struct {
		role  signature.SignerRole
		pubFn string
	}{
		{signature.SignerNode, NodeKeyPubFilename},
		{signature.SignerP2P, P2PKeyPubFilename},
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

	// TLS certificate.
	//
	// TODO: The key and cert could probably be made totally ephemeral, as long
	// as the registry update takes effect immediately.
	tlsCert, err := loadTLSCert(dataDir)
	if err != nil {
		if !os.IsNotExist(err) || !shouldGenerate {
			return nil, err
		}

		tlsCert, err = generateTLSCert(dataDir)
		if err != nil {
			return nil, err
		}
	}

	return &Identity{
		NodeSigner:     signers[0],
		P2PSigner:      signers[1],
		TLSKey:         tlsCert.PrivateKey.(*ecdsa.PrivateKey),
		TLSCertificate: tlsCert,
	}, nil
}

func tlsCertPaths(dataDir string) (string, string) {
	var (
		tlsKeyPath  = filepath.Join(dataDir, tlsKeyFilename)
		tlsCertPath = filepath.Join(dataDir, tlsCertFilename)
	)

	return tlsKeyPath, tlsCertPath
}

func loadTLSCert(dataDir string) (*tls.Certificate, error) {
	tlsKeyPath, tlsCertPath := tlsCertPaths(dataDir)

	// Decode key.
	tlsKeyPEM, err := ioutil.ReadFile(tlsKeyPath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(tlsKeyPEM)
	if blk == nil || blk.Type != tlsKeyPEMType {
		return nil, errors.New("failed to parse TLS private key")
	}
	tlsKey, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}

	// Decode certificate.
	tlsCertPEM, err := ioutil.ReadFile(tlsCertPath)
	if err != nil {
		return nil, err
	}
	blk, _ = pem.Decode(tlsCertPEM)
	if blk == nil || blk.Type != tlsCertPEMType {
		return nil, errors.New("failed to parse TLS certificate")
	}

	return &tls.Certificate{
		Certificate: [][]byte{blk.Bytes},
		PrivateKey:  tlsKey,
	}, nil
}

func generateTLSCert(dataDir string) (*tls.Certificate, error) {
	tlsKeyPath, tlsCertPath := tlsCertPaths(dataDir)

	// Generate a new X509 key pair.
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Persist key pair.
	der, err := x509.MarshalECPrivateKey(tlsKey)
	if err != nil {
		return nil, err
	}

	tlsKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tlsKeyPEMType,
		Bytes: der,
	})

	if err = ioutil.WriteFile(tlsKeyPath, tlsKeyPEM, 0600); err != nil {
		return nil, err
	}

	// Generate X509 certificate based on the key pair.
	certTemplate := tlsTemplate
	// Valid since one hour before issue.
	certTemplate.NotBefore = time.Now().Add(-1 * time.Hour)
	// Valid for one year.
	// TODO: Use shorter validity and support proper rotation while the node is running.
	certTemplate.NotAfter = time.Now().AddDate(1, 0, 0)
	tlsCertDer, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, tlsKey.Public(), tlsKey)
	if err != nil {
		return nil, err
	}

	// Persist TLS certificate.
	tlsCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  tlsCertPEMType,
		Bytes: tlsCertDer,
	})

	if err = ioutil.WriteFile(tlsCertPath, tlsCertPEM, 0644); err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{tlsCertDer},
		PrivateKey:  tlsKey,
	}, nil
}
