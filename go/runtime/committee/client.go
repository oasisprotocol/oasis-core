package committee

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/grpc/resolver/manual"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
)

// ClientConnWithMeta is a gRPC client connection together with node metadata.
type ClientConnWithMeta struct {
	*grpc.ClientConn

	Node *node.Node
}

// Client is a committee gRPC client interface. It automatically maintains gRPC connections to all
// nodes as directed by the committee watcher.
type Client interface {
	// GetConnections returns the set of connections to active committee nodes.
	GetConnections() []*grpc.ClientConn

	// GetConnectionsWith returns the set of connections to active committee nodes including node
	// metadata for each connection.
	GetConnectionsWithMeta() []*ClientConnWithMeta

	// GetConnection returns a connection.
	//
	// If no connections are available this method will return nil.
	//
	// TODO: Implement proper load-balancing policies.
	GetConnection() *grpc.ClientConn

	// EnsureVersion waits for the committee client to be fully synced to the given version.
	EnsureVersion(ctx context.Context, version int64) error

	// Initialized returns a channel that will be closed once the first connection is available.
	Initialized() <-chan struct{}
}

type clientConnState struct {
	node              *node.Node
	conn              *grpc.ClientConn
	resolverCleanupCb func()
}

type committeeClient struct {
	sync.RWMutex

	nw       NodeDescriptorLookup
	conns    map[signature.PublicKey]*clientConnState
	version  int64
	notifier *pubsub.Broker
	initCh   chan struct{}

	clientIdentity *identity.Identity

	logger *logging.Logger
}

func (cc *committeeClient) GetConnections() []*grpc.ClientConn {
	cc.RLock()
	defer cc.RUnlock()

	var conns []*grpc.ClientConn
	for _, c := range cc.conns {
		conns = append(conns, c.conn)
	}
	return conns
}

func (cc *committeeClient) GetConnectionsWithMeta() []*ClientConnWithMeta {
	cc.RLock()
	defer cc.RUnlock()

	var conns []*ClientConnWithMeta
	for _, c := range cc.conns {
		conns = append(conns, &ClientConnWithMeta{
			ClientConn: c.conn,
			Node:       c.node,
		})
	}
	return conns
}

func (cc *committeeClient) GetConnection() *grpc.ClientConn {
	cc.RLock()
	defer cc.RUnlock()

	for _, c := range cc.conns {
		return c.conn
	}
	return nil
}

func (cc *committeeClient) EnsureVersion(ctx context.Context, version int64) error {
	cc.RLock()
	if cc.version >= version {
		cc.RUnlock()
		return nil
	}

	// Wait for the version to become available.
	sub := cc.notifier.Subscribe()
	cc.RUnlock()

	defer sub.Close()
	ch := make(chan int64)
	sub.Unwrap(ch)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case v := <-ch:
			if v >= version {
				return nil
			}
		}
	}
}

func (cc *committeeClient) Initialized() <-chan struct{} {
	return cc.initCh
}

func (cc *committeeClient) updateConnectionLocked(n *node.Node) error {
	// Cleanup existing connection.
	var cs *clientConnState
	if cs = cc.conns[n.ID]; cs != nil {
		// Only update connections if keys or addresses have changed.
		if n.Committee.Equal(&cs.node.Committee) {
			cc.logger.Debug("not updating connection as addresses have not changed",
				"node", n,
			)
			return nil
		}

		if cs.conn != nil {
			cs.conn.Close()
		}
		if cs.resolverCleanupCb != nil {
			cs.resolverCleanupCb()
		}
	} else {
		cs = new(clientConnState)
		cc.conns[n.ID] = cs
	}
	cs.node = n

	// Setup resolver.
	certPool := x509.NewCertPool()
	for _, addr := range n.Committee.Addresses {
		nodeCert, err := addr.ParseCertificate()
		if err != nil {
			// This should never fail as the consensus layer should validate certificates.
			cc.logger.Warn("failed to parse TLS certificate for node",
				"err", err,
				"node", n,
			)
			return fmt.Errorf("failed to parse node certificate: %w", err)
		}

		certPool.AddCert(nodeCert)
	}

	// Create TLS credentials.
	tlsCfg := tls.Config{
		RootCAs:    certPool,
		ServerName: identity.CommonName,
	}
	if cc.clientIdentity != nil {
		// Configure TLS client authentication if required.
		tlsCfg.Certificates = []tls.Certificate{*cc.clientIdentity.TLSCertificate}
	}
	creds := credentials.NewTLS(&tlsCfg)

	manualResolver, address, cleanup := manual.NewManualResolver()
	cs.resolverCleanupCb = cleanup

	// Start dialing a gRPC connection to the given node.
	conn, err := cmnGrpc.Dial(
		address,
		grpc.WithTransportCredentials(creds),
		// https://github.com/grpc/grpc-go/issues/3003
		grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
	)
	if err != nil {
		cc.logger.Warn("failed to dial node",
			"err", err,
			"node", n,
		)
		return fmt.Errorf("failed to dial node: %w", err)
	}
	cs.conn = conn

	var resolverState resolver.State
	for _, addr := range n.Committee.Addresses {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	return nil
}

func (cc *committeeClient) deleteConnectionLocked(id signature.PublicKey) {
	cs := cc.conns[id]
	if cs == nil {
		return
	}

	if cs.conn != nil {
		cs.conn.Close()
	}
	if cs.resolverCleanupCb != nil {
		cs.resolverCleanupCb()
	}
	delete(cc.conns, id)
}

func (cc *committeeClient) worker(ctx context.Context, ch <-chan *NodeUpdate, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	var initialized bool
	for {
		select {
		case <-ctx.Done():
			return
		case u := <-ch:
			func() {
				cc.Lock()
				defer cc.Unlock()

				switch {
				case u.Reset:
					// Committee has been reset.
					for id := range cc.conns {
						cc.deleteConnectionLocked(id)
					}
				case u.Freeze != nil:
					// Committee has been frozen.
					cc.version = u.Freeze.Version
					cc.notifier.Broadcast(u.Freeze.Version)

					if !initialized {
						close(cc.initCh)
						initialized = true
					}
				case u.Update != nil:
					// Node information updated.
					cc.logger.Debug("updating node connection",
						"node", u.Update,
					)

					if err := cc.updateConnectionLocked(u.Update); err != nil {
						cc.logger.Error("failed to update gRPC connection to committee node",
							"err", err,
							"node", u.Update,
						)
						cc.deleteConnectionLocked(u.Update.ID)
					}
				default:
					cc.logger.Warn("ignoring unknown node update",
						"update", u,
					)
				}
			}()
		}
	}
}

// ClientOption is an option for NewClient.
type ClientOption func(cc *committeeClient)

// WithClientAuthentication is an option for configuring client authentication on TLS connections.
func WithClientAuthentication(identity *identity.Identity) ClientOption {
	return func(cc *committeeClient) {
		cc.clientIdentity = identity
	}
}

// NewClient creates a new committee client.
func NewClient(ctx context.Context, nw NodeDescriptorLookup, options ...ClientOption) (Client, error) {
	ch, sub, err := nw.WatchNodeUpdates()
	if err != nil {
		return nil, fmt.Errorf("committee: failed to watch for node updates: %w", err)
	}

	cc := &committeeClient{
		nw:       nw,
		conns:    make(map[signature.PublicKey]*clientConnState),
		notifier: pubsub.NewBroker(false),
		initCh:   make(chan struct{}),
		logger:   logging.GetLogger("runtime/committee/client"),
	}

	for _, o := range options {
		o(cc)
	}

	go cc.worker(ctx, ch, sub)

	return cc, nil
}
