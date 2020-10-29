// Package grpc provides nodes grpc connection utilities.
package grpc

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
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
)

const (
	defaultCloseDelay = 5 * time.Second

	// gRPC backoff max delay when establishing connections (default: 120).
	grpcBackoffMaxDelay = 10 * time.Second
	// Default.
	grpcMinConnectTimeout = 20 * time.Second
)

// ErrNotVersionedWatcher is an error returned when versioned specific methods are called
// for a non-versioned client.
var ErrNotVersionedWatcher = fmt.Errorf("client watcher is not versioned")

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

// ConnWithNodeMeta is a gRPC client connection together with node metadata.
type ConnWithNodeMeta struct {
	*grpc.ClientConn

	Node *node.Node
}

// NodesClient is a node gRPC client interface. It automatically maintains gRPC connections to all
// nodes as directed by the node watcher.
type NodesClient interface {
	// GetConnections returns the set of connections to nodes.
	GetConnections() []*grpc.ClientConn

	// GetConnectionsWithMeta returns the set of connections to nodes including node metadata
	// for each connection.
	GetConnectionsWithMeta() []*ConnWithNodeMeta

	// GetConnectionsMap returns the set of connections to nodes including node metadata
	// for each connection.
	GetConnectionsMap() map[signature.PublicKey]*ConnWithNodeMeta

	// GetConnection returns a connection based on the configured node selection policy.
	//
	// If no connections are available this method will return nil.
	GetConnection() *grpc.ClientConn

	// UpdateNodeSelectionPolicy submits feedback to the policy which can cause the policy to update
	// its current node selection.
	UpdateNodeSelectionPolicy(feedback NodeSelectionFeedback)

	// EnsureVersion waits for the client to be fully synced to the given watcher version.
	//
	// When client is using a non-versioned watcher, this method should return ErrNotVersionedWatcher error.
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

type nodesClient struct {
	sync.RWMutex

	nw       nodes.NodeDescriptorLookup
	conns    map[signature.PublicKey]*clientConnState
	version  int64
	notifier *pubsub.Broker
	initCh   chan struct{}

	clientIdentity      *identity.Identity
	nodeSelectionPolicy NodeSelectionPolicy
	closeDelay          time.Duration

	logger *logging.Logger
}

func (nc *nodesClient) GetConnections() []*grpc.ClientConn {
	nc.RLock()
	defer nc.RUnlock()

	var conns []*grpc.ClientConn
	for _, c := range nc.conns {
		conns = append(conns, c.conn)
	}
	return conns
}

func (nc *nodesClient) GetConnectionsWithMeta() []*ConnWithNodeMeta {
	nc.RLock()
	defer nc.RUnlock()

	var conns []*ConnWithNodeMeta
	for _, c := range nc.conns {
		conns = append(conns, &ConnWithNodeMeta{
			ClientConn: c.conn,
			Node:       c.node,
		})
	}
	return conns
}

func (nc *nodesClient) GetConnectionsMap() map[signature.PublicKey]*ConnWithNodeMeta {
	nc.RLock()
	defer nc.RUnlock()

	conns := make(map[signature.PublicKey]*ConnWithNodeMeta, len(nc.conns))
	for nodeID, c := range nc.conns {
		conns[nodeID] = &ConnWithNodeMeta{
			ClientConn: c.conn,
			Node:       c.node,
		}
	}
	return conns
}

func (nc *nodesClient) GetConnection() *grpc.ClientConn {
	nc.RLock()
	defer nc.RUnlock()

	if len(nc.conns) == 0 {
		return nil
	}

	id := nc.nodeSelectionPolicy.Pick()
	c := nc.conns[id]
	if c == nil {
		// Node selection policy may not have been updated yet.
		return nil
	}
	return c.conn
}

func (nc *nodesClient) UpdateNodeSelectionPolicy(feedback NodeSelectionFeedback) {
	nc.nodeSelectionPolicy.UpdatePolicy(feedback)
}

func (nc *nodesClient) EnsureVersion(ctx context.Context, version int64) error {
	if !nc.nw.Versioned() {
		return ErrNotVersionedWatcher
	}

	nc.RLock()
	if nc.version >= version {
		nc.RUnlock()
		return nil
	}

	// Wait for the version to become available.
	sub := nc.notifier.Subscribe()
	nc.RUnlock()

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

func (nc *nodesClient) Initialized() <-chan struct{} {
	return nc.initCh
}

func (nc *nodesClient) updateConnectionLocked(n *node.Node) error {
	// If the connection to given node already exists, only update its addresses/certificates.
	var cs *clientConnState
	if cs = nc.conns[n.ID]; cs != nil {
		// Only update connections if TLS keys or addresses have changed.
		if n.TLS.Equal(&cs.node.TLS) {
			nc.logger.Debug("not updating connection as TLS info has not changed",
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
				nc.RLock()
				keys := cs.tlsKeys
				nc.RUnlock()
				return keys, nil
			},
		}
		if nc.clientIdentity != nil {
			// Configure TLS client authentication if required.
			opts.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert := nc.clientIdentity.GetTLSCertificate()
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
			nc.logger.Warn("failed to dial node",
				"err", err,
				"node", n,
			)
			return fmt.Errorf("failed to dial node: %w", err)
		}
		cs.conn = conn

		nc.conns[n.ID] = cs
	}

	return cs.Update(n)
}

func (nc *nodesClient) deleteConnectionLocked(id signature.PublicKey) {
	cs := nc.conns[id]
	if cs == nil {
		return
	}

	cs.DelayedClose(nc.closeDelay)
	delete(nc.conns, id)
}

func (nc *nodesClient) refreshConnectionLocked(id signature.PublicKey) {
	cs := nc.conns[id]
	if cs == nil {
		return
	}

	if err := cs.Refresh(); err != nil {
		nc.logger.Error("failed to refresh connection",
			"err", err,
			"node", cs.node,
		)
		nc.deleteConnectionLocked(id)
	}
}

func (nc *nodesClient) worker(ctx context.Context, ch <-chan *nodes.NodeUpdate, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	// Subscribe to TLS certificate rotations if needed.
	var rotCh <-chan struct{}
	if nc.clientIdentity != nil {
		var rotSub pubsub.ClosableSubscription
		rotCh, rotSub = nc.clientIdentity.WatchCertificateRotations()
		defer rotSub.Close()
	}

	var initialized bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-rotCh:
			// Local TLS certificates have been rotated, we need to refresh connections.
			nc.logger.Debug("TLS certificates have been rotated, refreshing connections")

			func() {
				nc.Lock()
				defer nc.Unlock()

				for id := range nc.conns {
					nc.refreshConnectionLocked(id)
				}
			}()
		case u := <-ch:
			nc.logger.Debug("node update event received", "event", u)
			func() {
				nc.Lock()
				defer nc.Unlock()

				switch {
				case u.Reset:
					// Node watcher reset.
					for id := range nc.conns {
						nc.deleteConnectionLocked(id)
					}
				case u.Freeze != nil:
					if !nc.nw.Versioned() {
						nc.logger.Warn("versioned event for non-versioned node watcher",
							"event", u,
						)
						return
					}
					// Versioned node watcher - version freeze.
					nc.updateNodeSelectionPolicyLocked()

					nc.version = u.Freeze.Version
					nc.notifier.Broadcast(nc.version)

					if !initialized {
						close(nc.initCh)
						initialized = true
					}
				case u.BumpVersion != nil:
					if !nc.nw.Versioned() {
						nc.logger.Warn("versioned event for non-versioned node watcher",
							"event", u,
						)
						return
					}
					// Versioned node watcher, version bumped.
					nc.version = u.BumpVersion.Version
					nc.notifier.Broadcast(nc.version)
				case u.Update != nil:
					// Node information updated.
					if err := nc.updateConnectionLocked(u.Update); err != nil {
						nc.logger.Error("failed to update gRPC connection to node",
							"err", err,
							"node", u.Update,
						)
						nc.deleteConnectionLocked(u.Update.ID)
					}

					// If this is from a versioned watcher, nothing else to do as
					// this event only happens on existing node updates.
					if nc.nw.Versioned() {
						return
					}

					// Otherwise, initialize on first receive node.
					if !initialized {
						close(nc.initCh)
						initialized = true
					}

					// Update node selection policy.
					// XXX: could check if this is a new node, and only update in that case.
					nodes := make([]signature.PublicKey, 0, len(nc.conns))
					for id := range nc.conns {
						nodes = append(nodes, id)
					}
					nc.logger.Debug("updating node selection policy",
						"nodes", len(nodes),
					)
					nc.nodeSelectionPolicy.UpdateNodes(nodes)

				case u.Delete != nil:
					nc.logger.Debug("removing node connection",
						"node", u.Delete,
					)

					// In versioned watcher nodes can only be deleted in a version bump.
					if nc.nw.Versioned() {
						nc.logger.Warn("delete event for versioned node watcher",
							"event", u,
						)
						return
					}

					nc.deleteConnectionLocked(*u.Delete)

					// Update node selection policy.
					nodes := make([]signature.PublicKey, 0, len(nc.conns))
					for id := range nc.conns {
						nodes = append(nodes, id)
					}
					nc.logger.Debug("updating node selection policy",
						"nodes", len(nodes),
					)
					nc.nodeSelectionPolicy.UpdateNodes(nodes)

				default:
					nc.logger.Warn("ignoring unknown node update",
						"update", u,
					)
				}
			}()
		}
	}
}

// Option is an option for NewNodesClient.
type Option func(nc *nodesClient)

// WithClientAuthentication is an option for configuring client authentication on TLS connections.
func WithClientAuthentication(identity *identity.Identity) Option {
	return func(nc *nodesClient) {
		nc.clientIdentity = identity
	}
}

// WithNodeSelectionPolicy is an option for configuring the node selection policy.
//
// If not configured it defaults to the round-robin policy.
func WithNodeSelectionPolicy(policy NodeSelectionPolicy) Option {
	return func(nc *nodesClient) {
		nc.nodeSelectionPolicy = policy
	}
}

// WithCloseDelay is an option for configuring the connection close delay after rotating a
// connection.
//
// If not configured it defaults to 5 seconds.
func WithCloseDelay(delay time.Duration) Option {
	return func(nc *nodesClient) {
		nc.closeDelay = delay
	}
}

// NewNodesClient creates a new nodes gRPC client.
func NewNodesClient(ctx context.Context, nw nodes.NodeDescriptorLookup, options ...Option) (NodesClient, error) {
	ch, sub, err := nw.WatchNodeUpdates()
	if err != nil {
		return nil, fmt.Errorf("nodes/client: failed to watch for node updates: %w", err)
	}

	cc := &nodesClient{
		nw:                  nw,
		conns:               make(map[signature.PublicKey]*clientConnState),
		notifier:            pubsub.NewBroker(false),
		initCh:              make(chan struct{}),
		nodeSelectionPolicy: NewRoundRobinNodeSelectionPolicy(),
		closeDelay:          defaultCloseDelay,
		logger:              logging.GetLogger("runtime/nodes/client"),
	}

	for _, o := range options {
		o(cc)
	}

	go cc.worker(ctx, ch, sub)

	return cc, nil
}
