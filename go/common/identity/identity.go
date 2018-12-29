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
	nodeKeyFilename = "identity.pem"

	tlsKeyFilename = "tls-identity.pem"
	tlsKeyPEMType  = "EC PRIVATE KEY"
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

// LoadOrGenerate loads or generates an identity.
func LoadOrGenerate(dataDir string) (*Identity, error) {
	// Node key.
	var nodeKey signature.PrivateKey
	if err := nodeKey.LoadPEM(filepath.Join(dataDir, nodeKeyFilename), rand.Reader); err != nil {
		return nil, err
	}

	// TLS key and certificate.
	// TODO: We could use an ephemeral key pair as the node re-registers anyway.
	var tlsKey *ecdsa.PrivateKey
	var tlsCertDer []byte
	tlsKeyPath := filepath.Join(dataDir, tlsKeyFilename)
	tlsKeyPEM, err := ioutil.ReadFile(tlsKeyPath)
	if err == nil {
		// Decode key.
		blk, _ := pem.Decode(tlsKeyPEM)
		if blk == nil || blk.Type != tlsKeyPEMType {
			return nil, errors.New("failed to parse TLS private key")
		}

		tlsKey, err = x509.ParseECPrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
	} else {
		if !os.IsNotExist(err) {
			return nil, err
		}

		// Generate a new X509 key pair.
		tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		// Persist key pair.
		der, merr := x509.MarshalECPrivateKey(tlsKey)
		if merr != nil {
			return nil, merr
		}

		tlsKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  tlsKeyPEMType,
			Bytes: der,
		})

		if werr := ioutil.WriteFile(tlsKeyPath, tlsKeyPEM, 0600); werr != nil {
			return nil, werr
		}
	}

	// Generate X509 certificate based on the key pair. We generate a new
	// certificate on each startup so we can bump validity.
	certTemplate := tlsTemplate
	// Valid since one hour before issue.
	certTemplate.NotBefore = time.Now().Add(-1 * time.Hour)
	// Valid for one year.
	// TODO: Use shorter validity and support proper rotation while the node is running.
	certTemplate.NotAfter = time.Now().AddDate(1, 0, 0)
	tlsCertDer, err = x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, tlsKey.Public(), tlsKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{tlsCertDer},
		PrivateKey:  tlsKey,
	}

	return &Identity{
		NodeKey:        &nodeKey,
		TLSKey:         tlsKey,
		TLSCertificate: tlsCert,
	}, nil
}
