// Package api implements the sentry backend API.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// SentryAddresses contains sentry node consensus and TLS addresses.
type SentryAddresses struct {
	Consensus []node.ConsensusAddress `json:"consensus"`
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
}
