// Package client implements a client for Oasis sentry nodes.
package client

import (
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
)

var _ api.Backend = (*Client)(nil)

// Client is a sentry client for querying sentry nodes for their address(es).
type Client struct {
	api.Backend

	logger *logging.Logger

	sentryAddress node.TLSAddress
	identity      *identity.Identity

	conn *grpc.ClientConn
}

// Close closes the sentry client.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *Client) createConnection() error {
	// Setup a secure gRPC connection.
	creds, err := cmnGrpc.NewClientCreds(&cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			c.sentryAddress.PubKey: true,
		},
		Certificates: []tls.Certificate{*c.identity.TLSSentryClientCertificate},
	})
	if err != nil {
		return err
	}
	opts := grpc.WithTransportCredentials(creds)

	conn, err := cmnGrpc.Dial(c.sentryAddress.String(), opts) // nolint: staticcheck
	if err != nil {
		c.logger.Error("failed to dial the sentry node",
			"err", err,
		)
		return err
	}
	c.conn = conn
	c.Backend = api.NewSentryClient(conn)

	return nil
}

// New creates a new sentry client.
func New(sentryAddress node.TLSAddress, identity *identity.Identity) (*Client, error) {
	c := &Client{
		logger:        logging.GetLogger("sentry/client"),
		sentryAddress: sentryAddress,
		identity:      identity,
	}

	if err := c.createConnection(); err != nil {
		return nil, fmt.Errorf("failed to create a connection to sentry node: %w", err)
	}

	return c, nil
}
