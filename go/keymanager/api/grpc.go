package api

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// RegisterService registers a new keymanager backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	secrets.RegisterService(server, service.Secrets())
	churp.RegisterService(server, service.Churp())
}

// Client is a gRPC key manager client.
type Client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new gRPC key manager client.
func NewClient(c *grpc.ClientConn) *Client {
	return &Client{
		conn: c,
	}
}

func (c *Client) StateToGenesis(context.Context, int64) (*Genesis, error) {
	return nil, fmt.Errorf("keymanager: not supported")
}

func (c *Client) Secrets() secrets.Backend {
	return secrets.NewClient(c.conn)
}

func (c *Client) Churp() churp.Backend {
	return churp.NewClient(c.conn)
}
