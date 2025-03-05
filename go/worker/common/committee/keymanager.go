package committee

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core"
	"golang.org/x/exp/maps"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	runtimeKeymanager "github.com/oasisprotocol/oasis-core/go/runtime/keymanager/api"
	keymanagerP2P "github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
)

const (
	// peerFeedbackCacheSize is the maximum number of peer feedbacks
	// in the cache.
	peerFeedbackCacheSize = 100

	// maxPeerFeedbackAge is the maximum age of peer feedback in the cache
	// before it is discarded.
	maxPeerFeedbackAge = time.Minute
)

// KeyManagerClientWrapper is a wrapper for the key manager P2P client that handles deferred
// initialization after the key manager runtime ID is known.
//
// It also handles peer feedback propagation from EnclaveRPC in the runtime.
type KeyManagerClientWrapper struct {
	l sync.Mutex

	id           *common.Namespace
	p2p          p2p.Service
	consensus    consensus.Backend
	chainContext string
	cli          keymanagerP2P.Client
	nt           *nodeTracker
	logger       *logging.Logger

	lastPeerFeedback rpc.PeerFeedback
	peerFeedbacks    *lru.Cache
}

// Initialized returns a channel that gets closed when the client is initialized.
func (km *KeyManagerClientWrapper) Initialized() <-chan struct{} {
	km.l.Lock()
	defer km.l.Unlock()

	// If no active key manager client or node tracker, return a closed channel.
	if km.cli == nil || km.nt == nil {
		initCh := make(chan struct{})
		close(initCh)
		return initCh
	}

	return km.nt.Initialized()
}

// SetKeyManagerID configures the key manager runtime ID to use.
func (km *KeyManagerClientWrapper) SetKeyManagerID(id *common.Namespace) {
	km.l.Lock()
	defer km.l.Unlock()

	// Only reinitialize in case the key manager ID changes.
	if km.id == id || (km.id != nil && km.id.Equal(id)) {
		return
	}

	km.logger.Debug("key manager updated",
		"keymanager_id", id,
	)
	km.id = id

	if km.nt != nil {
		km.nt.Stop()
	}

	switch id {
	case nil:
		km.cli = nil
		km.nt = nil
	default:
		km.cli = keymanagerP2P.NewClient(km.p2p, km.chainContext, *id)
		km.nt = newKeyManagerNodeTracker(km.p2p, km.consensus, *id)
		km.nt.Start()
	}

	km.lastPeerFeedback = nil
	km.peerFeedbacks.Clear()
}

// CallEnclaveDeprecated implements runtimeKeymanager.Client.
func (km *KeyManagerClientWrapper) CallEnclaveDeprecated(
	ctx context.Context,
	data []byte,
	nodes []signature.PublicKey,
	kind enclaverpc.Kind,
	pf *enclaverpc.PeerFeedback,
) ([]byte, signature.PublicKey, error) {
	var node signature.PublicKey

	km.l.Lock()
	cli := km.cli
	lastPf := km.lastPeerFeedback
	km.l.Unlock()

	if cli == nil {
		return nil, node, fmt.Errorf("key manager not available")
	}

	// Propagate peer feedback on the last EnclaveRPC call to guide routing decision.
	if lastPf != nil {
		// If no feedback has been provided by the runtime, treat previous call as success.
		if pf == nil {
			pfv := enclaverpc.PeerFeedbackSuccess
			pf = &pfv
		}

		km.logger.Debug("received peer feedback from runtime",
			"peer_feedback", *pf,
		)

		switch *pf {
		case enclaverpc.PeerFeedbackSuccess:
			lastPf.RecordSuccess()
		case enclaverpc.PeerFeedbackFailure:
			lastPf.RecordFailure()
		case enclaverpc.PeerFeedbackBadPeer:
			lastPf.RecordBadPeer()
		default:
		}
	}

	// Call only members of the key manager committee. If no nodes are given, use all members.
	kmNodes := km.nt.Nodes(nodes)
	if len(kmNodes) == 0 && len(nodes) > 0 {
		return nil, node, fmt.Errorf("nodes not in committee")
	}
	peers := maps.Keys(kmNodes)

	req := &keymanagerP2P.CallEnclaveRequest{
		Data: data,
		Kind: kind,
	}

	rsp, nextPf, err := cli.CallEnclave(ctx, req, peers)
	if err != nil {
		return nil, node, err
	}

	node, ok := kmNodes[nextPf.PeerID()]
	if !ok {
		return nil, node, fmt.Errorf("unknown peer id")
	}

	// Store peer feedback instance that we can use.
	km.l.Lock()
	if km.cli == cli { // Key manager could get updated while we are doing the call.
		km.lastPeerFeedback = nextPf
	}
	km.l.Unlock()

	return rsp.Data, node, nil
}

// CallEnclave implements runtimeKeymanager.Client.
func (km *KeyManagerClientWrapper) CallEnclave(
	ctx context.Context,
	requestID uint64,
	data []byte,
	nodes []signature.PublicKey,
	kind enclaverpc.Kind,
) (*runtimeKeymanager.EnclaveResponse, error) {
	cli, err := km.getKeyManagerClient()
	if err != nil {
		return nil, err
	}

	// Call only members of the key manager committee. If no nodes are given, use all members.
	kmNodes := km.nt.Nodes(nodes)
	if len(kmNodes) == 0 && len(nodes) > 0 {
		return nil, fmt.Errorf("nodes not in committee")
	}
	peers := maps.Keys(kmNodes)

	req := &keymanagerP2P.CallEnclaveRequest{
		Data: data,
		Kind: kind,
	}

	rsp, feedback, err := cli.CallEnclave(ctx, req, peers)
	if err != nil {
		return nil, err
	}

	node, ok := kmNodes[feedback.PeerID()]
	if !ok {
		return nil, fmt.Errorf("unknown peer id")
	}

	info := peerFeedbackInfo{
		requestID: requestID,
		feedback:  feedback,
		timestamp: time.Now(),
	}

	// Put is expected to never fail since byte capacity is not enabled.
	_ = km.peerFeedbacks.Put(requestID, &info)

	return &runtimeKeymanager.EnclaveResponse{
		Data: rsp.Data,
		Node: node,
	}, nil
}

// SubmitPeerFeedback implements runtimeKeymanager.Client.
func (km *KeyManagerClientWrapper) SubmitPeerFeedback(requestID uint64, feedback enclaverpc.PeerFeedback) {
	var info *peerFeedbackInfo

	// Pop peer feedback info.
	item, ok := km.peerFeedbacks.Peek(requestID)
	if ok {
		_ = km.peerFeedbacks.Remove(requestID)
		info = item.(*peerFeedbackInfo)
	}

	// Discard expired feedbacks.
	valid := ok && time.Since(info.timestamp) <= maxPeerFeedbackAge

	km.logger.Debug("received peer feedback from runtime",
		"request_id", requestID,
		"peer_feedback", feedback,
		"valid", valid,
	)

	if !valid {
		return
	}

	switch feedback {
	case enclaverpc.PeerFeedbackSuccess:
		info.feedback.RecordSuccess()
	case enclaverpc.PeerFeedbackFailure:
		info.feedback.RecordFailure()
	case enclaverpc.PeerFeedbackBadPeer:
		info.feedback.RecordBadPeer()
	default:
	}
}

func (km *KeyManagerClientWrapper) getKeyManagerClient() (keymanagerP2P.Client, error) {
	km.l.Lock()
	defer km.l.Unlock()

	if km.cli == nil {
		return nil, fmt.Errorf("key manager not available")
	}
	return km.cli, nil
}

// NewKeyManagerClientWrapper creates a new key manager client wrapper.
func NewKeyManagerClientWrapper(p2p p2p.Service, consensus consensus.Backend, chainContext string, logger *logging.Logger) *KeyManagerClientWrapper {
	return &KeyManagerClientWrapper{
		p2p:           p2p,
		consensus:     consensus,
		chainContext:  chainContext,
		logger:        logger,
		peerFeedbacks: lru.New(lru.Capacity(peerFeedbackCacheSize, false)),
	}
}

type nodeTracker struct {
	sync.Mutex

	p2p          p2p.Service
	consensus    consensus.Backend
	keymanagerID common.Namespace

	nodes map[signature.PublicKey]core.PeerID

	initCh   chan struct{}
	startOne cmSync.One

	logger *logging.Logger
}

// Stop stops the node tracker if it is running.
func (nt *nodeTracker) Stop() {
	nt.startOne.TryStop()
}

// Start starts the node tracker if it is not running.
func (nt *nodeTracker) Start() {
	nt.startOne.TryStart(nt.trackKeymanagerNodes)
}

// Initialized returns a channel that closes when the tracker fetches nodes from the key manager
// status for the first time.
func (nt *nodeTracker) Initialized() <-chan struct{} {
	return nt.initCh
}

// Nodes returns a map of key manager node IDs and their peer identities for the given list
// of nodes. If no nodes given, all registered members of the key manager committee are returned.
func (nt *nodeTracker) Nodes(nodes []signature.PublicKey) map[core.PeerID]signature.PublicKey {
	nt.Lock()
	defer nt.Unlock()

	peers := make(map[core.PeerID]signature.PublicKey, len(nt.nodes))

	switch len(nodes) {
	case 0:
		for n, p := range nt.nodes {
			peers[p] = n
		}
	default:
		for _, n := range nodes {
			if p, ok := nt.nodes[n]; ok {
				peers[p] = n
			}
		}
	}

	return peers
}

func (nt *nodeTracker) trackKeymanagerNodes(ctx context.Context) {
	stCh, stSub, err := nt.consensus.KeyManager().Secrets().WatchStatuses(ctx)
	if err != nil {
		nt.logger.Error("failed to watch key manager secrets statuses",
			"err", err,
		)
		return
	}
	defer stSub.Close()

	for {
		var status *secrets.Status
		select {
		case <-ctx.Done():
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

		// Fetch key manager nodes from the consensus layer.
		nodes := make(map[signature.PublicKey]core.PeerID, len(status.Nodes))
		peers := make([]core.PeerID, 0, len(status.Nodes))
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

			nodes[node.ID] = peerID
			peers = append(peers, peerID)
		}

		// Mark them as important.
		if pm := nt.p2p.PeerManager(); pm != nil {
			pm.PeerTagger().SetPeerImportance(p2p.ImportantNodeKeyManager, nt.keymanagerID, peers)
		}

		// Update nodes.
		nt.Lock()
		nt.nodes = nodes
		nt.Unlock()

		// Signal initialization completed.
		select {
		case <-nt.initCh:
		default:
			nt.logger.Info("key manager is initialized",
				"id", status.ID,
				"status", status,
			)
			close(nt.initCh)
		}
	}
}

// newKeyManagerNodeTracker creates a new tracker that is responsible for keeping the list
// of key manager nodes and their peer identities up-to-date.
func newKeyManagerNodeTracker(p2p p2p.Service, consensus consensus.Backend, keymanagerID common.Namespace) *nodeTracker {
	return &nodeTracker{
		p2p:          p2p,
		consensus:    consensus,
		keymanagerID: keymanagerID,
		initCh:       make(chan struct{}),
		startOne:     cmSync.NewOne(),
		logger:       logging.GetLogger("worker/common/committee/keymanager/nodetracker"),
	}
}

// peerFeedbackInfo stores information related to peer feedback.
type peerFeedbackInfo struct {
	// requestID is the ID of the request.
	requestID uint64
	// feedback holds the peer feedback stored in this node.
	feedback rpc.PeerFeedback
	// timestamp is the time when the feedback was added to the cache.
	timestamp time.Time
}
