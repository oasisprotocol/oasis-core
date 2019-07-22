package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

// NewClientTLSConfigFromFile is a variant of the
// "google.golang.org/grpc/credentials".NewClientTLSFromFile function that
// returns a plain "crypto/tls".Config struct instead of wrapping it in the
// "google.golang.org/grpc/credentials".TransportCredentials object.
func NewClientTLSConfigFromFile(certFile, serverNameOverride string) (*tls.Config, error) {
	b, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("credentials: failed to append certificates")
	}
	return &tls.Config{ServerName: serverNameOverride, RootCAs: cp}, nil
}
