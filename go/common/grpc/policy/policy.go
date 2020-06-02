package policy

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/policy/api"
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
	return fmt.Sprintf("grpc: calling %v method for runtime %v not allowed for client %s", e.method, e.runtimeID, e.subject)
}

// GRPCStatus retruns appropriate gRPC status permission denied error code.
func (e ErrForbiddenByPolicy) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// GRPCAuthenticationFunction returns a gRPC authentication function using the provided
// policy checker.
func GRPCAuthenticationFunction(policy RuntimePolicyChecker) auth.AuthenticationFunction {
	return func(ctx context.Context, fullMethodName string, req interface{}) error {
		md, err := grpc.GetRegisteredMethod(fullMethodName)
		if err != nil {
			return status.Errorf(codes.PermissionDenied, "invalid request method")
		}

		ac, err := md.IsAccessControlled(ctx, req)
		if err != nil {
			return status.Errorf(codes.PermissionDenied, "internal error: %s", err.Error())
		}
		if !ac {
			return nil
		}

		namespace, err := md.ExtractNamespace(ctx, req)
		if err != nil {
			return status.Errorf(codes.PermissionDenied, "invalid request namespace")
		}

		return policy.CheckAccessAllowed(ctx, accessctl.Action(fullMethodName), namespace)
	}
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

	// service for which the policies are defined.
	service grpc.ServiceName

	// Map from runtime IDs to corresponding access control policies.
	accessPolicies map[common.Namespace]accessctl.Policy

	watcher api.PolicyWatcher
}

// SetAccessPolicy sets the PolicyChecker's access policy.
//
// After this method is called the passed policy must not be used anymore.
func (c *DynamicRuntimePolicyChecker) SetAccessPolicy(policy accessctl.Policy, runtimeID common.Namespace) {
	c.Lock()
	defer c.Unlock()

	c.accessPolicies[runtimeID] = policy

	if c.watcher != nil {
		// Create a snapshot of the access policies map. While each policy is immutable, the set of
		// all policies can be mutated by the dynamic runtime policy checker.
		policies := make(map[common.Namespace]accessctl.Policy, len(c.accessPolicies))
		for k, v := range c.accessPolicies {
			policies[k] = v
		}

		c.watcher.PolicyUpdated(c.service, policies)
	}
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
		return status.Errorf(codes.PermissionDenied, "grpc: failed to obtain connection peer from context")
	}
	tlsAuth, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Errorf(codes.PermissionDenied, "grpc: unexpected peer authentication credentials")
	}
	if nPeerCerts := len(tlsAuth.State.PeerCertificates); nPeerCerts != 1 {
		return status.Errorf(codes.PermissionDenied, fmt.Sprintf("grpc: unexpected number of peer certificates: %d", nPeerCerts))
	}
	peerCert := tlsAuth.State.PeerCertificates[0]
	subject := accessctl.SubjectFromX509Certificate(peerCert)
	policy := c.accessPolicies[runtimeID]

	// If no policy defined, reject.
	if policy == nil {
		return ErrForbiddenByPolicy{
			method:    method,
			runtimeID: runtimeID,
			subject:   string(subject),
		}
	}

	if !policy.IsAllowed(subject, method) {
		return ErrForbiddenByPolicy{
			method:    method,
			runtimeID: runtimeID,
			subject:   string(subject),
		}
	}

	// If forwarded subject metadata is present, also check the proxied
	// subject.
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.PermissionDenied, "grpc: failed getting metadata from context")
	}
	forwardedSubjects, ok := md[api.ForwardedSubjectMD]
	if !ok {
		// Not proxied through sentry, allow.
		return nil
	}
	if len(forwardedSubjects) != 1 {
		return status.Errorf(codes.PermissionDenied, "grpc: invalid subject metadata")
	}
	forwardedSubject := forwardedSubjects[0]
	if !policy.IsAllowed(accessctl.Subject(forwardedSubject), method) {
		return ErrForbiddenByPolicy{
			method:    method,
			runtimeID: runtimeID,
			subject:   forwardedSubject,
		}
	}
	return nil
}

// NewDynamicRuntimePolicyChecker creates a new dynamic runtime policy checker instance.
func NewDynamicRuntimePolicyChecker(service grpc.ServiceName, watcher api.PolicyWatcher) *DynamicRuntimePolicyChecker {
	return &DynamicRuntimePolicyChecker{
		accessPolicies: make(map[common.Namespace]accessctl.Policy),
		service:        service,
		watcher:        watcher,
	}
}
