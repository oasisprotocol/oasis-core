// Package client implements the Oasis IAS proxy client endpoint.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/ias/api"
	"github.com/oasisprotocol/oasis-core/go/ias/proxy"
)

var _ api.Endpoint = (*mockEndpoint)(nil)

type mockEndpoint struct{}

func (m *mockEndpoint) VerifyEvidence(_ context.Context, evidence *api.Evidence) (*ias.AVRBundle, error) {
	// Generate a mock AVR, under the assumption that the runtime is built to support this.
	// The runtime will reject the mock AVR if it is not.
	avr, err := ias.NewMockAVR(evidence.Quote, evidence.Nonce)
	if err != nil {
		return nil, err
	}
	return &ias.AVRBundle{
		Body: avr,
	}, nil
}

func (m *mockEndpoint) GetSPIDInfo(_ context.Context) (*api.SPIDInfo, error) {
	spidInfo := &api.SPIDInfo{}
	_ = spidInfo.SPID.UnmarshalBinary(make([]byte, ias.SPIDSize))
	return spidInfo, nil
}

func (m *mockEndpoint) GetSigRL(_ context.Context, _ uint32) ([]byte, error) {
	return nil, fmt.Errorf("IAS proxy is not configured, mock used")
}

func (m *mockEndpoint) Cleanup() {}

var _ api.Endpoint = (*proxyClient)(nil)

type proxyClient struct {
	conn     *grpc.ClientConn
	endpoint api.Endpoint

	logger *logging.Logger
}

func (c *proxyClient) VerifyEvidence(ctx context.Context, evidence *api.Evidence) (*ias.AVRBundle, error) {
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
	return c.endpoint.GetSPIDInfo(ctx)
}

func (c *proxyClient) GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error) {
	return c.endpoint.GetSigRL(ctx, epidGID)
}

func (c *proxyClient) Cleanup() {
	_ = c.conn.Close()
}

// New creates a collection of IAS proxy clients (one client per provided address).
func New(identity *identity.Identity, addresses []string) ([]api.Endpoint, error) {
	logger := logging.GetLogger("ias/proxyclient")

	if len(addresses) == 0 {
		logger.Warn("IAS proxy is not configured, all reports will be mocked")
		return []api.Endpoint{&mockEndpoint{}}, nil
	}

	clients := make([]api.Endpoint, 0, len(addresses))
	for _, addr := range addresses {
		spl := strings.Split(addr, "@")
		if len(spl) != 2 {
			return nil, fmt.Errorf("missing public key in address '%s'", addr)
		}

		var pk signature.PublicKey
		if err := pk.UnmarshalText([]byte(spl[0])); err != nil {
			return nil, fmt.Errorf("malformed public key in address '%s': %w", addr, err)
		}
		creds, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
			ServerPubKeys: map[signature.PublicKey]bool{pk: true},
			CommonName:    proxy.CommonName,
			GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return identity.TLSCertificate, nil
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create client credentials for address '%s': %w", addr, err)
		}
		conn, err := cmnGrpc.Dial(
			spl[1],
			grpc.WithTransportCredentials(creds),
			grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to dial IAS proxy address '%s': %w", addr, err)
		}

		clients = append(clients, &proxyClient{
			conn:     conn,
			endpoint: api.NewEndpointClient(conn),
			logger:   logger,
		})
	}

	return clients, nil
}
