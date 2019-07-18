package grpc

import (
	"context"
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/accessctl"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

// RuntimePolicyChecker is used for setting and checking the gRPC server's access control policy
// for different runtimes.
type RuntimePolicyChecker struct {
	sync.RWMutex

	// Map from runtime IDs to corresponding access control policies.
	accessPolicies map[signature.MapKey]*accessctl.Policy
}

// SetAccessPolicy sets the PolicyChecker's access policy.
func (c *RuntimePolicyChecker) SetAccessPolicy(policy *accessctl.Policy, runtimeID signature.PublicKey) {
	c.Lock()
	defer c.Unlock()

	c.accessPolicies[runtimeID.ToMapKey()] = policy
}

// GetAccessPolicy returns the PolicyChecker's current access policy.
func (c *RuntimePolicyChecker) GetAccessPolicy(runtimeID signature.PublicKey) *accessctl.Policy {
	c.RLock()
	defer c.RUnlock()

	return c.accessPolicies[runtimeID.ToMapKey()]
}

// CheckAccessAllowed checks if the connected peer is allowed access to a server method according
// to the set access policy.
func (c *RuntimePolicyChecker) CheckAccessAllowed(
	ctx context.Context,
	method accessctl.Action,
	namespace common.Namespace,
) error {
	c.RLock()
	defer c.RUnlock()

	runtimeID, err := namespace.ToRuntimeID()
	if err != nil {
		return errors.Wrap(err, "grpc: failed to derive runtime ID from namespace")
	}
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
	subject := accessctl.SubjectFromCertificate(peerCert)
	policy := c.accessPolicies[runtimeID.ToMapKey()]
	if policy == nil || !policy.IsAllowed(subject, method) {
		return fmt.Errorf("grpc: calling %v method for runtime %v not allowed for client %v", method, runtimeID, peerCert.Subject)
	}
	return nil
}

func NewRuntimePolicyChecker() RuntimePolicyChecker {
	return RuntimePolicyChecker{
		accessPolicies: make(map[signature.MapKey]*accessctl.Policy),
	}
}
