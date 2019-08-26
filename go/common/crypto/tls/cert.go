// Package tls implements helpful wrappers for dealing with TLS certificates.
package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/pkg/errors"
)

const (
	keyPEMType  = "EC PRIVATE KEY"
	certPEMType = "CERTIFICATE"
)

var certTemplate = x509.Certificate{
	SerialNumber: big.NewInt(1),
	KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
	ExtKeyUsage: []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	},
}

// LoadOrGenerate loads a TLS certificate and private key, or generates one
// iff they do not exist.
func LoadOrGenerate(certPath, keyPath, commonName string) (*tls.Certificate, error) {
	cert, err := Load(certPath, keyPath)
	if err == nil {
		return cert, nil
	}
	if !os.IsNotExist(err) {
		return nil, errors.Wrap(err, "tls: failed to load certificate or private key")
	}

	cert, err = Generate(commonName)
	if err != nil {
		return nil, err
	}

	if err = Save(certPath, keyPath, cert); err != nil {
		return nil, err
	}

	return cert, nil
}

// Generate generates a new TLS certificate.
func Generate(commonName string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "tls: failed to generate keypair")
	}

	// Tweak the template for the cert.
	//
	// TODO: The expiration period is probably too long, and could be reduced,
	// assuming the rest of the code gains the capability to refresh it.
	template := certTemplate
	template.Subject = pkix.Name{
		CommonName: commonName,
	}
	template.NotBefore = time.Now().Add(-1 * time.Hour)
	template.NotAfter = time.Now().AddDate(1, 0, 0)

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return nil, errors.Wrap(err, "tls: failed to create certificate")
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// Load loads a TLS certificate and private key.
func Load(certPath, keyPath string) (*tls.Certificate, error) {
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err // So os.IsNotExist(err) works.
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil || blk.Type != keyPEMType {
		return nil, errors.New("tls: failed to parse private key PEM")
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "tls: failed to parse private key")
	}

	cert, err := LoadCertificate(certPath)
	if err != nil {
		return nil, err
	}

	cert.PrivateKey = key
	return cert, nil
}

// LoadCertificate loads a TLS certificate.
func LoadCertificate(certPath string) (*tls.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err // So os.IsNotExist(err) works.
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != certPEMType {
		return nil, errors.New("tls: failed to parse certificate PEM")
	}

	return &tls.Certificate{
		Certificate: [][]byte{blk.Bytes},
	}, nil
}

// Save saves a TLS certificate and private key.
func Save(certPath, keyPath string, cert *tls.Certificate) error {
	der, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return errors.Wrap(err, "tls: failed to serialize private key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyPEMType,
		Bytes: der,
	})
	if err = ioutil.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return errors.Wrap(err, "tls: failed to write private key")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  certPEMType,
		Bytes: cert.Certificate[0],
	})
	if err = ioutil.WriteFile(certPath, certPEM, 0644); err != nil {
		return errors.Wrap(err, "tls: failed to write certificate")
	}

	return nil
}
