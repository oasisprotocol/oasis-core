// Package api defines the common gRPC policy service and data structures.
package api

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
)

const (
	// ForwardedSubjectMD is name of the metadata field in which the actual
	// subject should be passed in case sentry forwarded the request.
	ForwardedSubjectMD = "forwarded-subject"
)

// PolicyWatcher is a policy watcher interface.
type PolicyWatcher interface {
	// PolicyUpdated updates policies.
	PolicyUpdated(service grpc.ServiceName, accessPolicies map[common.Namespace]accessctl.Policy)
}

// SubjectFromGRPCContext tries to extract subject from TLS Certificate provided
// in the gRPC context.
func SubjectFromGRPCContext(ctx context.Context) (string, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("grpc: failed to obtain connection peer from context")
	}
	tlsAuth, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errors.New("grpc: unexpected peer authentication credentials")
	}
	if nPeerCerts := len(tlsAuth.State.PeerCertificates); nPeerCerts != 1 {
		return "", fmt.Errorf("grpc: unexpected number of peer certificates: %d", nPeerCerts)
	}
	peerCert := tlsAuth.State.PeerCertificates[0]
	subject := accessctl.SubjectFromX509Certificate(peerCert)

	return string(subject), nil
}
