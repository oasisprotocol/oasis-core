// Package api implements the sentry backend API.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// SentryAddresses contains sentry node consensus and TLS addresses.
type SentryAddresses struct {
	Consensus []node.ConsensusAddress `json:"consensus"`
	TLS       []node.TLSAddress       `json:"tls"`
}

// ServicePolicies contains policies for a GRPC service.
type ServicePolicies struct {
	Service        grpc.ServiceName                      `json:"service"`
	AccessPolicies map[common.Namespace]accessctl.Policy `json:"access_policies"`
}

// Backend is a sentry backend implementation.
type Backend interface {
	// Get addresses returns the list of consensus and TLS addresses of the sentry node.
	GetAddresses(context.Context) (*SentryAddresses, error)

	// SetUpstreamTLSPubKeys notifies the sentry node of the new TLS public keys used by its
	// upstream node.
	SetUpstreamTLSPubKeys(context.Context, []signature.PublicKey) error

	// GetUpstreamTLSPubKeys returns the TLS public keys of the sentry node's upstream node.
	GetUpstreamTLSPubKeys(context.Context) ([]signature.PublicKey, error)

	// UpdatePolicies notifies the sentry node of policy changes.
	UpdatePolicies(context.Context, ServicePolicies) error
}

// LocalBackend is a local sentry backend implementation.
type LocalBackend interface {
	Backend

	// GetPolicyChecker returns the current access policy checker for the given service.
	GetPolicyChecker(context.Context, grpc.ServiceName) (*policy.DynamicRuntimePolicyChecker, error)
}
