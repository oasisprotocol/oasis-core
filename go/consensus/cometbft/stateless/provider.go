package stateless

import (
	"crypto/tls"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// NewProvider creates a new consensus provider for the stateless client.
func NewProvider(address string, cert *tls.Certificate) (*consensusAPI.Client, error) {
	target, creds, err := createCredentials(address, cert)
	if err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	}

	conn, err := cmnGrpc.Dial(target, opts...)
	if err != nil {
		return nil, err
	}

	return consensusAPI.NewClient(conn), nil
}

func createCredentials(address string, cert *tls.Certificate) (string, credentials.TransportCredentials, error) {
	switch {
	case cmnGrpc.IsSocketAddress(address):
		return address, insecure.NewCredentials(), nil
	case !containsPublicKey(address):
		return address, credentials.NewTLS(&tls.Config{}), nil
	default:
		return createClientCredentials(address, cert)
	}
}

func createClientCredentials(address string, cert *tls.Certificate) (string, credentials.TransportCredentials, error) {
	key, target, _ := strings.Cut(address, "@")

	var pk signature.PublicKey
	if err := pk.UnmarshalText([]byte(key)); err != nil {
		return "", nil, fmt.Errorf("malformed address: %s", address)
	}

	opts := &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			pk: true,
		},
		Certificates: []tls.Certificate{
			*cert,
		},
	}

	creds, err := cmnGrpc.NewClientCreds(opts)
	if err != nil {
		return "", nil, err
	}

	return target, creds, nil
}

func containsPublicKey(address string) bool {
	return strings.Contains(address, "@")
}
