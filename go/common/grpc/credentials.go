package grpc

import (
	"crypto/tls"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/security/advancedtls"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	cmnTLS "github.com/oasislabs/oasis-core/go/common/crypto/tls"
)

// ClientOptions contains all the fields needed to configure a TLS client.
type ClientOptions struct {
	// CommonName is the expected certificate common name.
	CommonName string

	// ServerPubKeys is the set of public keys that are allowed to sign the server's certificate. If
	// this field is set GetServerPubKeys will be ignored.
	ServerPubKeys map[signature.PublicKey]bool

	// If GetServerPubKeys is set and ServerPubKeys is nil, GetServerPubKeys will be invoked every
	// time when verifying the server certificates.
	GetServerPubKeys func() (map[signature.PublicKey]bool, error)

	// If field Certificates is set, field GetClientCertificate will be ignored. The server will use
	// Certificates every time when asked for a certificate, without performing certificate
	// reloading.
	Certificates []tls.Certificate

	// If GetClientCertificate is set and Certificates is nil, the server will invoke this function
	// every time asked to present certificates to the client when a new connection is established.
	// This is known as peer certificate reloading.
	GetClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// NewClientCreds creates new client TLS transport credentials.
func NewClientCreds(opts *ClientOptions) (credentials.TransportCredentials, error) {
	return advancedtls.NewClientCreds(&advancedtls.ClientOptions{
		Certificates:         opts.Certificates,
		GetClientCertificate: opts.GetClientCertificate,
		VType:                advancedtls.SkipVerification,
		VerifyPeer: func(params *advancedtls.VerificationFuncParams) (*advancedtls.VerificationResults, error) {
			var err error
			keys := opts.ServerPubKeys
			if keys == nil && opts.GetServerPubKeys != nil {
				if keys, err = opts.GetServerPubKeys(); err != nil {
					return nil, err
				}
			}

			err = cmnTLS.VerifyCertificate(params.RawCerts, cmnTLS.VerifyOptions{
				CommonName: opts.CommonName,
				Keys:       keys,
			})
			if err != nil {
				return nil, err
			}

			return &advancedtls.VerificationResults{}, nil
		},
	})
}
