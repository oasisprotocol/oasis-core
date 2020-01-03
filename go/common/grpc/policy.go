package grpc

import (
	"context"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
)

var (
	_ RuntimePolicyChecker = (*AllowAllRuntimePolicyChecker)(nil)
	_ RuntimePolicyChecker = (*DynamicRuntimePolicyChecker)(nil)
)

// ErrForbiddenByPolicy is the error returned when an action is not allowed by policy.
type ErrForbiddenByPolicy struct {
	method    accessctl.Action
	runtimeID common.Namespace
	subject   string
}

func (e ErrForbiddenByPolicy) Error() string {
	return fmt.Sprintf("grpc: calling %v method for runtime %v not allowed for client %v", e.method, e.runtimeID, e.subject)
}

func (e ErrForbiddenByPolicy) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// RuntimePolicyChecker is used for setting and checking the gRPC server's access control policy
// for different runtimes.
type RuntimePolicyChecker interface {
	// CheckAccessAllowed checks if the connected peer is allowed access to a server method according
	// to the set access policy.
	CheckAccessAllowed(ctx context.Context, method accessctl.Action, namespace common.Namespace) error
}

// AllowAllRuntimePolicyChecker is a RuntimePolicyChecker that allows all access.
type AllowAllRuntimePolicyChecker struct{}

func (c *AllowAllRuntimePolicyChecker) CheckAccessAllowed(ctx context.Context, method accessctl.Action, namespace common.Namespace) error {
	return nil
}

// DynamicRuntimePolicyChecker is a RuntimePolicyChecker that allows a dynamic policy to be
// specified and modified.
type DynamicRuntimePolicyChecker struct {
	sync.RWMutex

	// Map from runtime IDs to corresponding access control policies.
	accessPolicies map[common.Namespace]accessctl.Policy
}

// SetAccessPolicy sets the PolicyChecker's access policy.
//
// After this method is called the passed policy must not be used anymore.
func (c *DynamicRuntimePolicyChecker) SetAccessPolicy(policy accessctl.Policy, runtimeID common.Namespace) {
	c.Lock()
	defer c.Unlock()

	c.accessPolicies[runtimeID] = policy
}

// CheckAccessAllowed checks if the connected peer is allowed access to a server method according
// to the set access policy.
func (c *DynamicRuntimePolicyChecker) CheckAccessAllowed(
	ctx context.Context,
	method accessctl.Action,
	runtimeID common.Namespace,
) error {
	c.RLock()
	defer c.RUnlock()

	peer, ok := peer.FromContext(ctx)
	if !ok {
		return errors.New("grpc: failed to obtain connection peer from context")
	}
	tlsAuth, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return errors.New("grpc: unexpected peer authentication credentials")
	}
	if nPeerCerts := len(tlsAuth.State.PeerCertificates); nPeerCerts != 1 {
		return fmt.Errorf("grpc: unexpected number of peer certificates: %d", nPeerCerts)
	}
	peerCert := tlsAuth.State.PeerCertificates[0]
	subject := accessctl.SubjectFromX509Certificate(peerCert)
	policy := c.accessPolicies[runtimeID]
	if policy == nil || !policy.IsAllowed(subject, method) {
		return ErrForbiddenByPolicy{
			method:    method,
			runtimeID: runtimeID,
			subject:   peerCert.Subject.String(),
		}
	}
	return nil
}

// NewDynamicRuntimePolicyChecker creates a new dynamic runtime policy checker instance.
func NewDynamicRuntimePolicyChecker() *DynamicRuntimePolicyChecker {
	return &DynamicRuntimePolicyChecker{
		accessPolicies: make(map[common.Namespace]accessctl.Policy),
	}
}
