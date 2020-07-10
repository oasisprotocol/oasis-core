// Package tls implements helpful wrappers for dealing with TLS certificates.
package tls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

const (
	keyPEMType  = "PRIVATE KEY"
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
		return nil, fmt.Errorf("tls: failed to load certificate or private key: %w", err)
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
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to generate keypair: %w", err)
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

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to create certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

// Load loads a TLS certificate and private key.
func Load(certPath, keyPath string) (*tls.Certificate, error) {
	keyPEM, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err // So os.IsNotExist(err) works.
	}
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err // So os.IsNotExist(err) works.
	}
	return ImportPEM(certPEM, keyPEM)
}

// ImportPEM loads a TLS certificate and private key from in-memory PEM blobs.
func ImportPEM(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil || blk.Type != keyPEMType {
		return nil, fmt.Errorf("tls: failed to parse private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to parse private key: %w", err)
	}

	cert, err := ImportCertificatePEM(certPEM)
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
	return ImportCertificatePEM(certPEM)
}

// ImportCertificatePEM loads a TLS certificate from an in-memory PEM blob.
func ImportCertificatePEM(certPEM []byte) (*tls.Certificate, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != certPEMType {
		return nil, fmt.Errorf("tls: failed to parse certificate PEM")
	}

	return &tls.Certificate{
		Certificate: [][]byte{blk.Bytes},
	}, nil
}

// Save saves a TLS certificate and private key.
func Save(certPath, keyPath string, cert *tls.Certificate) error {
	certPEM, keyPEM, err := ExportPEM(cert)
	if err != nil {
		return err
	}

	if err = ioutil.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("tls: failed to write private key: %w", err)
	}

	if err = ioutil.WriteFile(certPath, certPEM, 0o644); err != nil { // nolint: gosec
		return fmt.Errorf("tls: failed to write certificate: %w", err)
	}

	return nil
}

// ExportPEM saves a TLS certificate and private key into PEM blobs.
func ExportPEM(cert *tls.Certificate) ([]byte, []byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: failed to serialize private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyPEMType,
		Bytes: der,
	})

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  certPEMType,
		Bytes: cert.Certificate[0],
	})

	return certPEM, keyPEM, nil
}
