// Package client implements a client for Oasis sentry nodes.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/oasis-core/go/common/grpc/resolver/manual"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/grpc/sentry"
	"github.com/oasislabs/oasis-core/go/sentry/api"
)

var (
	_ api.Backend = (*Client)(nil)
)

var (
	// ErrSentryNotAvailable is the error returned when the sentry node is not
	// available.
	ErrSentryNotAvailable = errors.New("sentry/client: sentry node not available")
)

// Client is a sentry client for querying sentry nodes for their address(es).
type Client struct {
	logger *logging.Logger

	sentryAddress *node.Address
	sentryCert    *x509.Certificate

	nodeIdentity *identity.Identity

	client            sentry.SentryClient
	conn              *grpc.ClientConn
	resolverCleanupFn func()
}

// Close closes the sentry client.
func (c *Client) Close() {
	if c.resolverCleanupFn != nil {
		c.resolverCleanupFn()
		c.resolverCleanupFn = nil
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// GetConsensusAddresses returns the list of sentry node's consensus addresses.
func (c *Client) GetConsensusAddresses(ctx context.Context) ([]node.ConsensusAddress, error) {
	if c.client == nil {
		return nil, ErrSentryNotAvailable
	}

	var req sentry.GetConsensusAddressesRequest

	resp, err := c.client.GetConsensusAddresses(ctx, &req)
	if err != nil {
		return nil, err
	}

	addresses, err := node.FromProtoConsensusAddresses(resp.Addresses)
	if err != nil {
		return nil, err
	}

	return addresses, nil
}

func (c *Client) createConnection() error {
	// Setup a secure gRPC connection.
	certPool := x509.NewCertPool()
	certPool.AddCert(c.sentryCert)
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{*c.nodeIdentity.TLSCertificate},
		RootCAs:      certPool,
		ServerName:   identity.CommonName,
	})
	opts := grpc.WithTransportCredentials(creds)

	// NOTE: While this may look screwed up, the resolver needs the client
	// connection before populating addresses.
	// Dialing is deferred until use, which can't happen.
	manualResolver, address, cleanupFn := manual.NewManualResolver()
	conn, err := grpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name)) //nolint: staticcheck
	if err != nil {
		cleanupFn()
		c.logger.Error("failed to dial the sentry node",
			"err", err,
		)
		return err
	}
	c.conn = conn
	c.resolverCleanupFn = cleanupFn
	c.client = sentry.NewSentryClient(c.conn)

	var resolverState resolver.State
	resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: c.sentryAddress.String()})
	manualResolver.UpdateState(resolverState)

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
