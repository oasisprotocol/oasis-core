// Package client implements the Oasis IAS proxy client endpoint.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/ias/api"
	"github.com/oasisprotocol/oasis-core/go/ias/proxy"
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
	if c.endpoint == nil {
		return nil, fmt.Errorf("IAS proxy is not configured, mock used")
	}
	return c.endpoint.GetSigRL(ctx, epidGID)
}

func (c *proxyClient) Cleanup() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// New creates a new IAS proxy client endpoint.
func New(identity *identity.Identity, addresses []string) (api.Endpoint, error) {
	c := &proxyClient{
		identity: identity,
		logger:   logging.GetLogger("ias/proxyclient"),
	}

	if len(addresses) == 0 {
		c.logger.Warn("IAS proxy is not configured, all reports will be mocked")

		c.spidInfo = &api.SPIDInfo{}
		_ = c.spidInfo.SPID.UnmarshalBinary(make([]byte, ias.SPIDSize))
	} else {
		var resolverState resolver.State
		pubKeys := make(map[signature.PublicKey]bool)
		for _, addr := range addresses {
			spl := strings.Split(addr, "@")
			if len(spl) != 2 {
				return nil, fmt.Errorf("missing public key in address '%s'", addr)
			}

			var pk signature.PublicKey
			if err := pk.UnmarshalText([]byte(spl[0])); err != nil {
				return nil, fmt.Errorf("malformed public key in address '%s': %w", addr, err)
			}

			pubKeys[pk] = true
			resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: spl[1]})
		}

		creds, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
			ServerPubKeys: pubKeys,
			CommonName:    proxy.CommonName,
			GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return identity.GetTLSCertificate(), nil
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create client credentials: %w", err)
		}

		manualResolver := manual.NewBuilderWithScheme("oasis-core-resolver")
		conn, err := cmnGrpc.Dial(
			"oasis-core-resolver:///",
			grpc.WithTransportCredentials(creds),
			// https://github.com/grpc/grpc-go/issues/3003
			grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
			grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
			grpc.WithResolvers(manualResolver),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to dial IAS proxy: %w", err)
		}

		manualResolver.UpdateState(resolverState)

		c.conn = conn
		c.endpoint = api.NewEndpointClient(conn)
	}

	return c, nil
}
