// Package client implements the key manager client.
package client

import (
	"context"
	"crypto/x509"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/worker/common/enclaverpc"
)

const (
	cfgDebugClientAddress = "keymanager.debug.client.address"
	cfgDebugClientCert    = "keymanager.debug.client.certificate"

	kmEndpoint = "key-manager"
)

var (
	ErrKeyManagerNotAvailable = errors.New("keymanager/client: key manager not available")
)

// Client is a key manager client instance.
type Client struct {
	sync.RWMutex

	logger *logging.Logger

	registry          registry.Backend
	conn              *grpc.ClientConn
	client            *enclaverpc.Client
	resolverCleanupFn func()
}

// CallRemote calls a runtime-specific key manager via remote EnclaveRPC.
func (c *Client) CallRemote(ctx context.Context, runtimeID signature.PublicKey, data []byte) ([]byte, error) {
	c.RLock()
	defer c.RUnlock()
	if c.client == nil {
		return nil, ErrKeyManagerNotAvailable
	}

	// TODO: The runtimeID is currently entirely ignored.  `data` also contains
	// a runtimeID for the purpose of separating keys.

	return c.client.CallEnclave(ctx, data)
}

func (c *Client) worker() {
	// TODO: The "correct" way to implement this is to schedule the key manager,
	// but for now just work under the assumption that this is running on staging
	// and or prod, and there is only one KM node registered at once, that all
	// the runtimes will use.

	ch, sub := c.registry.WatchNodeList()
	defer sub.Close()

	findFirstKMNode := func(l []*node.Node) *node.Node {
		for _, n := range l {
			if n.HasRoles(node.RoleKeyManager) {
				return n
			}
		}
		return nil
	}

	for nl := range ch {
		c.logger.Debug("updating node list",
			"epoch", nl.Epoch,
		)

		c.updateConnection(findFirstKMNode(nl.Nodes))
	}
}

func (c *Client) updateConnection(n *node.Node) {
	if n == nil {
		c.logger.Error("failed to update connection, no key manager nodes found")
		return
	}

	if n.Certificate == nil {
		// TODO: The registry should reject such registrations, so this should never happen.
		c.logger.Error("key manager node registered without certificate, refusing to communicate",
			"node_id", n.ID,
		)
		return
	}

	// TODO: Only update the connection if the key or address changed.
	c.Lock()
	defer c.Unlock()

	cert, err := n.Certificate.Parse()
	if err != nil {
		c.logger.Error("failed to parse key manager certificate",
			"err", err,
		)
		return
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	creds := credentials.NewClientTLSFromCert(certPool, "ekiden-node")
	opts := grpc.WithTransportCredentials(creds)

	if c.resolverCleanupFn != nil {
		c.resolverCleanupFn()
		c.resolverCleanupFn = nil
	}
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	// Note: While this may look screwed up, the resolver needs the client conn
	// before populating addresses, dialing is defered till use, which can't
	// happen.
	manualResolver, address, cleanupFn := manual.NewManualResolver()
	conn, err := grpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name))
	if err != nil {
		c.logger.Error("failed to create new gRPC client",
			"err", err,
		)
		return
	}
	var addresses []resolver.Address
	for _, addr := range n.Addresses {
		addresses = append(addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.NewAddress(addresses)

	c.logger.Debug("updated connection",
		"node", n,
	)

	c.client = enclaverpc.NewFromConn(conn, kmEndpoint)
	c.conn = conn
	c.resolverCleanupFn = cleanupFn
}

// New creates a new key manager client instance.
func New(registryBackend registry.Backend) (*Client, error) {
	c := &Client{
		logger: logging.GetLogger("keymanager/client"),
	}

	if debugAddress := viper.GetString(cfgDebugClientAddress); debugAddress != "" {
		debugCert := viper.GetString(cfgDebugClientCert)

		client, err := enclaverpc.NewClient(debugAddress, debugCert, kmEndpoint)
		if err != nil {
			return nil, errors.Wrap(err, "keymanager/client: failed to create debug client")
		}

		c.client = client

		return c, nil
	}

	// Standard configuration watches the various backends.
	c.registry = registryBackend
	go c.worker()

	return c, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgDebugClientAddress, "", "Key manager address")
		cmd.Flags().String(cfgDebugClientCert, "", "Key manager TLS certificate")
	}

	for _, v := range []string{
		cfgDebugClientAddress,
		cfgDebugClientCert,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
