package auth

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
)

// PeerCertAuthenticator is a server side gRPC authentication function
// that restricts access to all methods based on the hash of the DER
// representation of the client certificate presented in the TLS handshake.
type PeerCertAuthenticator struct {
	sync.RWMutex

	whitelist map[accessctl.Subject]bool
}

// AuthFunc is an AuthenticationFunction backed by the PeerCertAuthenticator.
func (auth *PeerCertAuthenticator) AuthFunc(ctx context.Context, fullMethodName string, req interface{}) error {
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

	auth.RLock()
	defer auth.RUnlock()
	if !auth.whitelist[subject] {
		return status.Errorf(codes.PermissionDenied, "grpc: unknown peer certificate")
	}

	return nil
}

// AllowPeerCertificate allows a peer certificate access.
func (auth *PeerCertAuthenticator) AllowPeerCertificate(cert *x509.Certificate) {
	subject := accessctl.SubjectFromX509Certificate(cert)

	auth.Lock()
	defer auth.Unlock()
	auth.whitelist[subject] = true
}

// NewPeerCertAuthenticator creates a new (empty) PeerCertAuthenticator.
func NewPeerCertAuthenticator() *PeerCertAuthenticator {
	return &PeerCertAuthenticator{
		whitelist: make(map[accessctl.Subject]bool),
	}
}
