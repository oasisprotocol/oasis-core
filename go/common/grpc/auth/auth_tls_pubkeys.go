package auth

import (
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnTLS "github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
)

// PeerPubkeyAuthenticator is a server side gRPC authentication function
// that restricts access to all methods based on the public keys of the client
// certificate presented in the TLS handshake.
type PeerPubkeyAuthenticator struct {
	sync.RWMutex

	whitelist map[signature.PublicKey]bool
}

// AuthFunc is an AuthenticationFunction backed by the PeerPubkeyAuthenticator.
func (auth *PeerPubkeyAuthenticator) AuthFunc(ctx context.Context, fullMethodName string, req interface{}) error {
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
	peerCertRaw := tlsAuth.State.PeerCertificates[0].Raw

	auth.RLock()
	defer auth.RUnlock()
	err := cmnTLS.VerifyCertificate([][]byte{peerCertRaw}, cmnTLS.VerifyOptions{
		CommonName: identity.CommonName,
		Keys:       auth.whitelist,
	})
	if err != nil {
		return status.Errorf(codes.PermissionDenied, err.Error())
	}

	return nil
}

// AllowPeerPublicKey allows a peer public key access.
func (auth *PeerPubkeyAuthenticator) AllowPeerPublicKey(key signature.PublicKey) {
	auth.Lock()
	defer auth.Unlock()
	auth.whitelist[key] = true
}

// NewPeerPubkeyAuthenticator creates a new (empty) PeerPubkeyAuthenticator.
func NewPeerPubkeyAuthenticator() *PeerPubkeyAuthenticator {
	return &PeerPubkeyAuthenticator{
		whitelist: make(map[signature.PublicKey]bool),
	}
}
