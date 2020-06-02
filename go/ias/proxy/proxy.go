// Package proxy implements the Oasis IAS proxy endpoint.
package proxy

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/ias/api"
)

// CommonName is the CommonName for the IAS proxy TLS certificate.
const CommonName = "ias-proxy"

var _ api.Endpoint = (*proxyEndpoint)(nil)

// Authenticator is the interface used to authenticate gRPC requests.
type Authenticator interface {
	// VerifyEvidence returns nil iff the signer's evidenice may attest
	// via the gRPC server.
	//
	// Caller authentication information may be derived from the context.
	VerifyEvidence(ctx context.Context, evidence *api.Evidence) error
}

type noOpAuthenticator struct{}

func (n *noOpAuthenticator) VerifyEvidence(ctx context.Context, evidence *api.Evidence) error {
	return nil
}

type proxyEndpoint struct {
	endpoint      api.Endpoint
	authenticator Authenticator

	logger *logging.Logger
}

func (p *proxyEndpoint) VerifyEvidence(ctx context.Context, evidence *api.Evidence) (*ias.AVRBundle, error) {
	if err := p.authenticator.VerifyEvidence(ctx, evidence); err != nil {
		p.logger.Warn("failed to authenticate IAS VerifyEvidence request",
			"err", err,
		)
		return nil, err
	}

	return p.endpoint.VerifyEvidence(ctx, evidence)
}

func (p *proxyEndpoint) GetSPIDInfo(ctx context.Context) (*api.SPIDInfo, error) {
	return p.endpoint.GetSPIDInfo(ctx)
}

func (p *proxyEndpoint) GetSigRL(ctx context.Context, epidGID uint32) ([]byte, error) {
	// TODO: Validate the EPID group ID.
	return p.endpoint.GetSigRL(ctx, epidGID)
}

func (p *proxyEndpoint) Cleanup() {
}

// New creates a new proxy endpoint.
func New(endpoint api.Endpoint, authenticator Authenticator) api.Endpoint {
	if authenticator == nil {
		authenticator = &noOpAuthenticator{}
	}

	return &proxyEndpoint{
		endpoint:      endpoint,
		authenticator: authenticator,
		logger:        logging.GetLogger("ias/proxy"),
	}
}
