package grpc

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/oasislabs/ekiden/go/common/accessctl"
)

// CheckAllowed checks if the connected peer is allowed access to a server method according to the given access policy.
func CheckAllowed(serverCtx context.Context, policy accessctl.Policy, method accessctl.Action) error {
	peer, ok := peer.FromContext(serverCtx)
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
	if !policy.IsAllowed(subject, method) {
		return fmt.Errorf("grpc: calling %v method not allowed for client %v", method, peerCert.Subject)
	}
	return nil
}
