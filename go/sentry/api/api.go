// Package api implements the sentry backend API.
package api

import (
	"context"
	"crypto/tls"

	"github.com/oasislabs/oasis-core/go/common/node"
)

// SentryAddresses contains sentry node consensus and committee addresses.
type SentryAddresses struct {
	Consensus []node.ConsensusAddress
	Committee []node.CommitteeAddress
}

// UpstreamTLSCertificates contains the upstream TLS certificates.
type UpstreamTLSCertificates struct {
	Certificate     *tls.Certificate
	NextCertificate *tls.Certificate
}

// Backend is a sentry backend implementation.
type Backend interface {
	// Get addresses returns the list of consensus and committee addresses of
	// the sentry node.
	GetAddresses(context.Context) (*SentryAddresses, error)

	// SetUpstreamTLSCertificates notifies the sentry node of the new
	// TLS certificates used by its upstream node.
	SetUpstreamTLSCertificates(context.Context, *tls.Certificate, *tls.Certificate) error

	// GetUpstreamTLSCertificates returns the TLS certificates of the sentry node's upstream node.
	GetUpstreamTLSCertificates(context.Context) (*UpstreamTLSCertificates, error)
}
