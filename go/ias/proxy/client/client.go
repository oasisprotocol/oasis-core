// Package client implements the Oasis IAS proxy client endpoint.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	tlsCert "github.com/oasislabs/oasis-core/go/common/crypto/tls"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/ias/api"
	"github.com/oasislabs/oasis-core/go/ias/proxy"
)

var _ api.Endpoint = (*proxyClient)(nil)

type proxyClient struct {
	identity *identity.Identity

	conn     *grpc.ClientConn
	endpoint api.Endpoint

	spidInfo *api.SPIDInfo

	logger *logging.Logger
}

func (c *proxyClient) fetchSPIDInfo(ctx context.Context) error {
	if c.spidInfo != nil || c.endpoint == nil {
		return nil
	}

	var err error
	if c.spidInfo, err = c.endpoint.GetSPIDInfo(ctx); err != nil {
		return err
	}
	return nil
}

func (c *proxyClient) VerifyEvidence(ctx context.Context, evidence *api.Evidence) (*ias.AVRBundle, error) {
	if c.endpoint == nil {
		// If the IAS proxy is not configured, generate a mock AVR, under the
		// assumption that the runtime is built to support this.  The runtime
		// will reject the mock AVR if it is not.
		avr, err := ias.NewMockAVR(evidence.Quote, evidence.Nonce)
		if err != nil {
			return nil, err
		}
		return &ias.AVRBundle{
			Body: avr,
		}, nil
	}

	// Ensure the evidence.Quote passes basic sanity/security checks before
	// even bothering to contact the backend.
	var untrustedQuote ias.Quote
	if err := untrustedQuote.UnmarshalBinary(evidence.Quote); err != nil {
		return nil, err
	}
	if err := untrustedQuote.Verify(); err != nil {
		return nil, err
	}

	return c.endpoint.VerifyEvidence(ctx, evidence)
}

func (c *proxyClient) GetSPIDInfo(ctx context.Context) (*api.SPIDInfo, error) {
	if err := c.fetchSPIDInfo(ctx); err != nil {
		return nil, err
	}
	return c.spidInfo, nil
}

func (c *proxyClient) GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error) {
	return c.endpoint.GetSigRL(ctx, epidGID)
}

func (c *proxyClient) Cleanup() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// New creates a new IAS proxy client endpoint.
func New(identity *identity.Identity, proxyAddr, tlsCertFile string) (api.Endpoint, error) {
	c := &proxyClient{
		identity: identity,
		logger:   logging.GetLogger("ias/proxyclient"),
	}

	if proxyAddr == "" {
		c.logger.Warn("IAS proxy is not configured, all reports will be mocked")

		c.spidInfo = &api.SPIDInfo{}
		_ = c.spidInfo.SPID.UnmarshalBinary(make([]byte, ias.SPIDSize))
	} else {
		if tlsCertFile == "" {
			c.logger.Error("IAS proxy TLS certificate not configured")
			return nil, errors.New("ias: proxy TLS certificate not configured")
		}

		proxyCert, err := tlsCert.LoadCertificate(tlsCertFile)
		if err != nil {
			return nil, err
		}

		parsedCert, err := x509.ParseCertificate(proxyCert.Certificate[0])
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		certPool.AddCert(parsedCert)
		creds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{*identity.TLSCertificate},
			RootCAs:      certPool,
			ServerName:   proxy.CommonName,
		})

		conn, err := cmnGrpc.Dial(
			proxyAddr,
			grpc.WithTransportCredentials(creds),
			grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		)
		if err != nil {
			return nil, err
		}
		c.conn = conn
		c.endpoint = api.NewEndpointClient(conn)
	}

	return c, nil
}
