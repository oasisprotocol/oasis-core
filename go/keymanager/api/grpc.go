package api

import (
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// RegisterService registers a new keymanager backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	secrets.RegisterService(server, service.Secrets())
}

// KeymanagerClient is a gRPC keymanager client.
type KeymanagerClient struct {
	secretsClient *secrets.Client
}

func (c *KeymanagerClient) Secrets() *secrets.Client {
	return c.secretsClient
}

// NewKeymanagerClient creates a new gRPC keymanager client service.
func NewKeymanagerClient(c *grpc.ClientConn) *KeymanagerClient {
	return &KeymanagerClient{
		secretsClient: secrets.NewClient(c),
	}
}
