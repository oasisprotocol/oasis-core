// Package enclaverpc implements the enclave RPC client.
package enclaverpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	erpcGrpc "github.com/oasislabs/ekiden/go/grpc/enclaverpc"
)

// Client is an enclave RPC client.
type Client struct {
	conn   *grpc.ClientConn
	client erpcGrpc.EnclaveRpcClient

	enclaveID []byte
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
		EnclaveId: c.enclaveID,
		Payload:   request,
	}
	res, err := c.client.CallEnclave(ctx, &req)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

// NewClient creates a new enclave RPC client instance.
func NewClient(address string, certFile string, enclaveID []byte) (*Client, error) {
	creds, err := credentials.NewClientTLSFromFile(certFile, "ekiden-node")
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

	c := &Client{
		conn:      conn,
		client:    erpcGrpc.NewEnclaveRpcClient(conn),
		enclaveID: enclaveID,
	}
	return c, nil
}
