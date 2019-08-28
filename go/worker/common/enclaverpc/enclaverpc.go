// Package enclaverpc implements the enclave RPC client.
package enclaverpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/oasislabs/ekiden/go/common/identity"
	erpcGrpc "github.com/oasislabs/ekiden/go/grpc/enclaverpc"
)

// Client is an enclave RPC client.
type Client struct {
	conn   *grpc.ClientConn
	client erpcGrpc.EnclaveRpcClient

	endpoint string
}

// Close the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// CallEnclave sends the request bytes to the target enclave.
func (c *Client) CallEnclave(ctx context.Context, request []byte) ([]byte, error) {
	req := erpcGrpc.CallEnclaveRequest{
		Endpoint: c.endpoint,
		Payload:  request,
	}
	res, err := c.client.CallEnclave(ctx, &req)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

// NewClient creates a new enclave RPC client instance.
func NewClient(address string, certFile string, endpoint string) (*Client, error) {
	creds, err := credentials.NewClientTLSFromFile(certFile, identity.CommonName)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(
		address,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, err
	}

	return NewFromConn(conn, endpoint), nil
}

// NewFromConn creates a new enclave RPC client instance with a pre-established
// gRPC connection.
func NewFromConn(conn *grpc.ClientConn, endpoint string) *Client {
	return &Client{
		conn:     conn,
		client:   erpcGrpc.NewEnclaveRpcClient(conn),
		endpoint: endpoint,
	}
}
