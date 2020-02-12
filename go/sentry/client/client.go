// Package client implements a client for Oasis sentry nodes.
package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/sentry/api"
)

var _ api.Backend = (*Client)(nil)

// Client is a sentry client for querying sentry nodes for their address(es).
type Client struct {
	api.Backend

	logger *logging.Logger

	sentryAddress *node.Address
	sentryCert    *x509.Certificate

	nodeIdentity *identity.Identity

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
	certPool := x509.NewCertPool()
	certPool.AddCert(c.sentryCert)
	creds := credentials.NewTLS(&tls.Config{
		RootCAs:    certPool,
		ServerName: identity.CommonName,
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return c.nodeIdentity.GetTLSCertificate(), nil
		},
	})
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
func New(
	sentryAddress *node.Address,
	sentryCert *x509.Certificate,
	nodeIdentity *identity.Identity,
) (*Client, error) {
	c := &Client{
		logger:        logging.GetLogger("sentry/client"),
		sentryAddress: sentryAddress,
		sentryCert:    sentryCert,
		nodeIdentity:  nodeIdentity,
	}

	if err := c.createConnection(); err != nil {
		return nil, fmt.Errorf("failed to create a connection to sentry node: %w", err)
	}

	return c, nil
}
