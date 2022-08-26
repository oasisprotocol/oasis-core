package p2p

import (
	"context"
	"sync"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	p2p "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

// Client is a keymanager protocol client.
type Client interface {
	// CallEnclave calls a key manager enclave with the provided data.
	CallEnclave(ctx context.Context, request *CallEnclaveRequest) (*CallEnclaveResponse, rpc.PeerFeedback, error)

	// Stop asks the client to stop.
	Stop()

	// Initialized returns a channel that gets closed when the client is initialized.
	Initialized() <-chan struct{}
}

type client struct {
	rc rpc.Client
	nt *nodeTracker
}

func (c *client) CallEnclave(ctx context.Context, request *CallEnclaveRequest) (*CallEnclaveResponse, rpc.PeerFeedback, error) {
	var rsp CallEnclaveResponse
	pf, err := c.rc.Call(ctx, MethodCallEnclave, request, &rsp, MaxCallEnclaveResponseTime,
		rpc.WithMaxRetries(MaxCallEnclaveRetries),
		rpc.WithRetryInterval(CallEnclaveRetryInterval),
	)
	if err != nil {
		return nil, nil, err
	}
	return &rsp, pf, nil
}

func (c *client) Stop() {
	close(c.nt.stopCh)
}

func (c *client) Initialized() <-chan struct{} {
	return c.nt.initCh
}

type nodeTracker struct {
	sync.Mutex

	p2p          p2p.Service
	consensus    consensus.Backend
	keymanagerID common.Namespace

	peers map[core.PeerID]bool

	initCh chan struct{}
	stopCh chan struct{}

	logger *logging.Logger
}

// Implements rpc.PeerFilter.
func (nt *nodeTracker) IsPeerAcceptable(peerID core.PeerID) bool {
	nt.Lock()
	defer nt.Unlock()

	return nt.peers[peerID]
}

func (nt *nodeTracker) trackKeymanagerNodes() {
	stCh, stSub := nt.consensus.KeyManager().WatchStatuses()
	defer stSub.Close()

	ctx := context.Background()

	var initialized bool
	for {
		var status *keymanager.Status
		select {
		case <-nt.stopCh:
			return
		case st := <-stCh:
			// Ignore status updates if key manager is not yet known (is nil) or if the status
			// update is for a different key manager.
			if !st.ID.Equal(&nt.keymanagerID) {
				continue
			}

			status = st
		}

		// It's not possible to service requests for this key manager.
		if !status.IsInitialized || len(status.Nodes) == 0 {
			nt.logger.Warn("key manager not initialized or has no nodes",
				"id", status.ID,
				"status", status,
			)
			continue
		}

		// Clear peer map and add nodes to filter.
		nt.Lock()
		nt.peers = make(map[core.PeerID]bool)
		peerKeys := make(map[signature.PublicKey]bool)
		for _, nodeID := range status.Nodes {
			node, err := nt.consensus.Registry().GetNode(ctx, &registry.IDQuery{
				ID:     nodeID,
				Height: consensus.HeightLatest,
			})
			if err != nil {
				nt.logger.Warn("failed to fetch node descriptor",
					"err", err,
					"node_id", nodeID,
				)
				continue
			}

			peerID, err := p2p.PublicKeyToPeerID(node.P2P.ID)
			if err != nil {
				nt.logger.Warn("failed to derive peer ID",
					"err", err,
					"node_id", nodeID,
				)
				continue
			}

			nt.peers[peerID] = true
			peerKeys[node.P2P.ID] = true
		}
		// Mark key manager nodes as important.
		nt.p2p.SetNodeImportance(p2p.ImportantNodeKeyManager, nt.keymanagerID, peerKeys)
		nt.Unlock()

		// Signal initialization completed.
		if !initialized {
			nt.logger.Info("key manager is initialized",
				"id", status.ID,
				"status", status,
			)

			close(nt.initCh)
			initialized = true
		}
	}
}

// NewClient creates a new keymanager protocol client.
func NewClient(p2p p2p.Service, consensus consensus.Backend, keymanagerID common.Namespace) Client {
	// Create a peer filter as we want the client to only talk to known key manager nodes.
	nt := &nodeTracker{
		p2p:          p2p,
		consensus:    consensus,
		keymanagerID: keymanagerID,
		initCh:       make(chan struct{}),
		stopCh:       make(chan struct{}),
		logger:       logging.GetLogger("worker/keymanager/p2p/nodetracker"),
	}
	go nt.trackKeymanagerNodes()

	return &client{
		rc: rpc.NewClient(p2p, keymanagerID, KeyManagerProtocolID, KeyManagerProtocolVersion,
			rpc.WithStickyPeers(true),
			rpc.WithPeerFilter(nt),
		),
		nt: nt,
	}
}
