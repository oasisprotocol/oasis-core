package committee

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

const (
	defaultCloseDelay = 5 * time.Second

	// gRPC backoff max delay when establishing connections (default: 120).
	grpcBackoffMaxDelay = 10 * time.Second
	// Default.
	grpcMinConnectTimeout = 20 * time.Second
)

// NodeSelectionFeedback is feedback to the node selection policy.
type NodeSelectionFeedback struct {
	// ID is the node identifier.
	ID signature.PublicKey

	// Bad being non-nil signals that the currently selected node is bad and contains the reason
	// that lead to the decision.
	Bad error
}

// NodeSelectionPolicy is a node selection policy.
type NodeSelectionPolicy interface {
	// UpdateNodes updates the set of available nodes.
	UpdateNodes([]signature.PublicKey)

	// UpdatePolicy submits feedback to the policy which can cause the policy to update its current
	// node selection.
	UpdatePolicy(feedback NodeSelectionFeedback)

	// Pick picks a node from the set of available nodes accoording to the policy.
	Pick() signature.PublicKey
}

type roundRobinNodeSelectionPolicy struct {
	sync.Mutex

	nodes []signature.PublicKey
	index int
}

func (rr *roundRobinNodeSelectionPolicy) UpdateNodes(nodes []signature.PublicKey) {
	// Randomly shuffle the nodes to avoid all nodes using the same order.
	rng := rand.New(mathrand.New(cryptorand.Reader))
	rng.Shuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	})

	rr.Lock()
	defer rr.Unlock()

	// Restore the node that was picked last if possible to avoid the node changing just because of
	// a new randomized order.
	var newIndex int
	if len(rr.nodes) > 0 {
		lastNode := rr.nodes[rr.index]
		for idx, n := range nodes {
			if n.Equal(lastNode) {
				newIndex = idx
				break
			}
		}
	}

	rr.nodes = nodes
	rr.index = newIndex
}

func (rr *roundRobinNodeSelectionPolicy) Pick() signature.PublicKey {
	rr.Lock()
	defer rr.Unlock()

	if len(rr.nodes) == 0 {
		return signature.PublicKey{}
	}
	return rr.nodes[rr.index]
}

func (rr *roundRobinNodeSelectionPolicy) UpdatePolicy(feedback NodeSelectionFeedback) {
	if feedback.Bad == nil {
		// Don't rotate nodes if the feedback was good.
		return
	}

	rr.Lock()
	defer rr.Unlock()

	if len(rr.nodes) == 0 {
		return
	}

	// The round-robin policy ignores any bad feedback.
	rr.index = (rr.index + 1) % len(rr.nodes)
}

// NewRoundRobinNodeSelectionPolicy creates a new round-robin node selection policy.
func NewRoundRobinNodeSelectionPolicy() NodeSelectionPolicy {
	return &roundRobinNodeSelectionPolicy{}
}

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

	// GetConnection returns a connection based on the configured node selection policy.
	//
	// If no connections are available this method will return nil.
	GetConnection() *grpc.ClientConn

	// UpdateNodeSelectionPolicy submits feedback to the policy which can cause the policy to update
	// its current node selection.
	UpdateNodeSelectionPolicy(feedback NodeSelectionFeedback)

	// EnsureVersion waits for the committee client to be fully synced to the given version.
	EnsureVersion(ctx context.Context, version int64) error

	// Initialized returns a channel that will be closed once the first connection is available.
	Initialized() <-chan struct{}
}

type clientConnState struct {
	node *node.Node
	conn *grpc.ClientConn

	tlsKeys map[signature.PublicKey]bool

	resolver *manual.Resolver
}

// Refresh refreshes the node connection without closing the virtual connection.
func (cs *clientConnState) Refresh() error {
	cs.resolver.UpdateState(resolver.State{})
	return cs.Update(cs.node)
}

// Update updates the node connection information without closing the connection.
func (cs *clientConnState) Update(n *node.Node) error {
	// Update node descriptor.
	cs.node = n

	// Update addresses and TLS keys. The resolver will propagate addresses to the gRPC load
	// balancer which will internally update subconns based on address changes.
	var resolverState resolver.State
	cs.tlsKeys = make(map[signature.PublicKey]bool)
	for _, addr := range n.TLS.Addresses {
		cs.tlsKeys[addr.PubKey] = true
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	cs.resolver.UpdateState(resolverState)

	return nil
}

// DelayedClose closes the connection after the given delay. This method does not block the caller.
func (cs *clientConnState) DelayedClose(delay time.Duration) {
	go func() {
		time.Sleep(delay)
		cs.Close()
	}()
}

// Close closes the connection.
func (cs *clientConnState) Close() {
	if cs.conn != nil {
		cs.conn.Close()
		cs.conn = nil
	}
}

type committeeClient struct {
	sync.RWMutex

	nw       NodeDescriptorLookup
	conns    map[signature.PublicKey]*clientConnState
	version  int64
	notifier *pubsub.Broker
	initCh   chan struct{}

	clientIdentity      *identity.Identity
	nodeSelectionPolicy NodeSelectionPolicy
	closeDelay          time.Duration

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

	if len(cc.conns) == 0 {
		return nil
	}

	id := cc.nodeSelectionPolicy.Pick()
	c := cc.conns[id]
	if c == nil {
		// Node selection policy may not have been updated yet.
		return nil
	}
	return c.conn
}

func (cc *committeeClient) UpdateNodeSelectionPolicy(feedback NodeSelectionFeedback) {
	cc.nodeSelectionPolicy.UpdatePolicy(feedback)
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
	// If the connection to given node already exists, only update its addresses/certificates.
	var cs *clientConnState
	if cs = cc.conns[n.ID]; cs != nil {
		// Only update connections if TLS keys or addresses have changed.
		if n.TLS.Equal(&cs.node.TLS) {
			cc.logger.Debug("not updating connection as TLS info has not changed",
				"node", n,
			)
			return nil
		}
	} else {
		// Create a new connection.
		cs = new(clientConnState)

		// Create TLS credentials.
		opts := cmnGrpc.ClientOptions{
			CommonName: identity.CommonName,
			GetServerPubKeys: func() (map[signature.PublicKey]bool, error) {
				cc.RLock()
				keys := cs.tlsKeys
				cc.RUnlock()
				return keys, nil
			},
		}
		if cc.clientIdentity != nil {
			// Configure TLS client authentication if required.
			opts.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert := cc.clientIdentity.GetTLSCertificate()
				if cert == nil {
					return &tls.Certificate{}, nil
				}
				return cert, nil
			}
		}

		creds, err := cmnGrpc.NewClientCreds(&opts)
		if err != nil {
			return fmt.Errorf("failed to create TLS client credentials: %w", err)
		}

		// NOTE: The scheme does not need to be unique as this resolver is not global.
		cs.resolver = manual.NewBuilderWithScheme("oasis-core-resolver")
		cs.resolver.InitialState(resolver.State{})

		// Backoff config.
		backoffConfig := backoff.DefaultConfig
		backoffConfig.MaxDelay = grpcBackoffMaxDelay

		// Create a virtual connection to the given node.
		conn, err := cmnGrpc.Dial(
			"oasis-core-resolver:///",
			grpc.WithTransportCredentials(creds),
			// https://github.com/grpc/grpc-go/issues/3003
			grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
			grpc.WithResolvers(cs.resolver),
			grpc.WithConnectParams(
				grpc.ConnectParams{
					Backoff:           backoffConfig,
					MinConnectTimeout: grpcMinConnectTimeout,
				},
			),
		)
		if err != nil {
			cc.logger.Warn("failed to dial node",
				"err", err,
				"node", n,
			)
			return fmt.Errorf("failed to dial node: %w", err)
		}
		cs.conn = conn

		cc.conns[n.ID] = cs
	}

	return cs.Update(n)
}

func (cc *committeeClient) deleteConnectionLocked(id signature.PublicKey) {
	cs := cc.conns[id]
	if cs == nil {
		return
	}

	cs.DelayedClose(cc.closeDelay)
	delete(cc.conns, id)
}

func (cc *committeeClient) refreshConnectionLocked(id signature.PublicKey) {
	cs := cc.conns[id]
	if cs == nil {
		return
	}

	if err := cs.Refresh(); err != nil {
		cc.logger.Error("failed to refresh connection",
			"err", err,
			"node", cs.node,
		)
		cc.deleteConnectionLocked(id)
	}
}

func (cc *committeeClient) worker(ctx context.Context, ch <-chan *NodeUpdate, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	// Subscribe to TLS certificate rotations if needed.
	var rotCh <-chan struct{}
	if cc.clientIdentity != nil {
		var rotSub pubsub.ClosableSubscription
		rotCh, rotSub = cc.clientIdentity.WatchCertificateRotations()
		defer rotSub.Close()
	}

	var initialized bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-rotCh:
			// Local TLS certificates have been rotated, we need to refresh connections.
			cc.logger.Debug("TLS certificates have been rotated, refreshing connections")

			func() {
				cc.Lock()
				defer cc.Unlock()

				for id := range cc.conns {
					cc.refreshConnectionLocked(id)
				}
			}()
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
					var nodes []signature.PublicKey
					for id := range cc.conns {
						nodes = append(nodes, id)
					}
					cc.nodeSelectionPolicy.UpdateNodes(nodes)

					cc.version = u.Freeze.Version
					cc.notifier.Broadcast(cc.version)

					if !initialized {
						close(cc.initCh)
						initialized = true
					}
				case u.BumpVersion != nil:
					// Committee version has been bumped while committee stayed the same.
					cc.version = u.BumpVersion.Version
					cc.notifier.Broadcast(cc.version)
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

// WithNodeSelectionPolicy is an option for configuring the node selection policy.
//
// If not configured it defaults to the round-robin policy.
func WithNodeSelectionPolicy(policy NodeSelectionPolicy) ClientOption {
	return func(cc *committeeClient) {
		cc.nodeSelectionPolicy = policy
	}
}

// WithCloseDelay is an option for configuring the connection close delay after rotating a
// connection.
//
// If not configured it defaults to 5 seconds.
func WithCloseDelay(delay time.Duration) ClientOption {
	return func(cc *committeeClient) {
		cc.closeDelay = delay
	}
}

// NewClient creates a new committee client.
func NewClient(ctx context.Context, nw NodeDescriptorLookup, options ...ClientOption) (Client, error) {
	ch, sub, err := nw.WatchNodeUpdates()
	if err != nil {
		return nil, fmt.Errorf("committee: failed to watch for node updates: %w", err)
	}

	cc := &committeeClient{
		nw:                  nw,
		conns:               make(map[signature.PublicKey]*clientConnState),
		notifier:            pubsub.NewBroker(false),
		initCh:              make(chan struct{}),
		nodeSelectionPolicy: NewRoundRobinNodeSelectionPolicy(),
		closeDelay:          defaultCloseDelay,
		logger:              logging.GetLogger("runtime/committee/client"),
	}

	for _, o := range options {
		o(cc)
	}

	go cc.worker(ctx, ch, sub)

	return cc, nil
}
