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
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

const (
	nodeKeyPrivFilename = "identity.pem"
	nodeKeyPubFilename  = "identity_pub.pem"

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
	// NodeKey is a node private key.
	NodeKey *signature.PrivateKey
	// TLSKey is a private key used for TLS connections.
	TLSKey *ecdsa.PrivateKey
	// TLSCertificate is a certificate that can be used for TLS.
	TLSCertificate *tls.Certificate
}

// Load loads an identity.
func Load(dataDir string) (*Identity, error) {
	return doLoadOrGenerate(dataDir, false)
}

// LoadOrGenerate loads or generates an identity.
func LoadOrGenerate(dataDir string) (*Identity, error) {
	return doLoadOrGenerate(dataDir, true)
}

func doLoadOrGenerate(dataDir string, shouldGenerate bool) (*Identity, error) {
	var rng io.Reader
	if shouldGenerate {
		rng = rand.Reader
	}

	// Node key.
	var nodeKey signature.PrivateKey
	if err := nodeKey.LoadPEM(filepath.Join(dataDir, nodeKeyPrivFilename), rng); err != nil {
		return nil, err
	}
	var nodePub signature.PublicKey
	if err := nodePub.LoadPEM(filepath.Join(dataDir, nodeKeyPubFilename), &nodeKey); err != nil {
		return nil, err
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
		NodeKey:        &nodeKey,
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
