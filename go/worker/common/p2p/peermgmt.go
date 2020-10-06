package p2p

import (
	"context"
	"fmt"
	"sync"

	"github.com/cenkalti/backoff/v4"
	core "github.com/libp2p/go-libp2p-core"
	"github.com/libp2p/go-libp2p-core/peer"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
)

// PeerManager handles managing peers in the gossipsub network.
//
// XXX: we accept connections from all peers, however known peers
// from registry are considered trustworthier and we maintain persistent
// connections with them. Once libp2p layer supports "peer reputation" configure
// better reputation for registry peers.
type PeerManager struct {
	sync.RWMutex

	ctx context.Context

	host  core.Host
	peers map[core.PeerID]*p2pPeer

	logger *logging.Logger
}

type p2pPeer struct {
	ctx      context.Context
	cancelFn context.CancelFunc

	addrHash hash.Hash

	doneCh chan struct{}
}

// SetNodes sets the membership of the gossipsub network.
func (mgr *PeerManager) SetNodes(nodes []*node.Node) {
	mgr.Lock()
	defer mgr.Unlock()

	newNodes := make(map[core.PeerID]*node.Node)
	for _, node := range nodes {
		peerID, err := publicKeyToPeerID(node.P2P.ID)
		if err != nil {
			mgr.logger.Warn("error while getting peer ID from public key, skipping",
				"err", err,
				"node_id", node.ID,
			)
			continue
		}

		newNodes[peerID] = node
	}

	// Remove existing peers that are not in the new node list.
	for peerID := range mgr.peers {
		node := newNodes[peerID]
		if node == nil {
			mgr.removePeerLocked(peerID)
			continue
		}
	}

	// Update peers from the new node list.
	for peerID, node := range newNodes {
		mgr.updateNodeLocked(node, peerID)
	}

	mgr.logger.Debug("updated peer list, outgoing connections started",
		"num_nodes", len(mgr.peers),
	)
}

// UpdateNode upserts a node into the gossipsub network.
func (mgr *PeerManager) UpdateNode(node *node.Node) error {
	peerID, err := publicKeyToPeerID(node.P2P.ID)
	if err != nil {
		return fmt.Errorf("worker/common/p2p/peermgr: failed to get peer ID from public key: %w", err)
	}

	mgr.Lock()
	defer mgr.Unlock()

	mgr.updateNodeLocked(node, peerID)

	return nil
}

func (mgr *PeerManager) removePeerLocked(peerID core.PeerID) {
	if existing := mgr.peers[peerID]; existing != nil {
		existing.cancelFn()
		<-existing.doneCh

		mgr.peers[peerID] = nil
	}
}

func (mgr *PeerManager) updateNodeLocked(node *node.Node, peerID core.PeerID) {
	var addrHash hash.Hash
	addrHash.From(node.P2P.Addresses)

	// If this is an update, and the addresses have not changed in any
	// way, then don't bother doing anything.
	if oldNode := mgr.peers[peerID]; oldNode != nil {
		if oldNode.addrHash.Equal(&addrHash) {
			return
		}
	}

	// Cancel any existing connection attempts to the peer.
	mgr.removePeerLocked(peerID)

	peer := &p2pPeer{
		addrHash: addrHash,
		doneCh:   make(chan struct{}),
	}
	peer.ctx, peer.cancelFn = context.WithCancel(mgr.ctx)
	mgr.peers[peerID] = peer

	go peer.connectWorker(mgr, node, peerID)
}

func (mgr *PeerManager) watchRegistryNodes(consensus consensus.Backend) {
	// Watch the registry for node changes, and attempt to keep the
	// gossipsub peer list up to date.

	nodeListCh, nlSub, err := consensus.Registry().WatchNodeList(mgr.ctx)
	if err != nil {
		mgr.logger.Error("failed to watch registry for node list changes",
			"err", err,
		)
		return
	}
	defer nlSub.Close()

	nodeCh, nSub, err := consensus.Registry().WatchNodes(mgr.ctx)
	if err != nil {
		mgr.logger.Error("failed to watch registry for node changes",
			"err", err,
		)
		return
	}
	defer nSub.Close()

	for {
		select {
		case <-mgr.ctx.Done():
			break
		case nodeList := <-nodeListCh:
			mgr.SetNodes(nodeList.Nodes)
		case nodeEv := <-nodeCh:
			if nodeEv.IsRegistration {
				_ = mgr.UpdateNode(nodeEv.Node)
			}
		}
	}
}

func newPeerManager(ctx context.Context, host core.Host, consensus consensus.Backend) *PeerManager {
	mgr := &PeerManager{
		ctx:    ctx,
		host:   host,
		peers:  make(map[core.PeerID]*p2pPeer),
		logger: logging.GetLogger("worker/common/p2p/peermgr"),
	}
	if consensus != nil {
		go mgr.watchRegistryNodes(consensus)
	}
	return mgr
}

func (p *p2pPeer) connectWorker(mgr *PeerManager, node *node.Node, peerID core.PeerID) {
	defer func() {
		close(p.doneCh)
	}()

	ai, err := nodeToAddrInfo(node)
	if err != nil {
		mgr.logger.Error("failed to get node addresses, not retrying",
			"err", err,
			"node_id", node.ID,
		)
		return
	}

	mgr.logger.Debug("updating libp2p gossipsub peer",
		"node_id", node.ID,
	)

	bctx := backoff.WithContext(backoff.NewExponentialBackOff(), p.ctx)

	err = backoff.Retry(func() error {
		// This is blocking, which is stupid.
		if perr := mgr.host.Connect(p.ctx, *ai); perr != nil {
			switch perr {
			case context.Canceled, context.DeadlineExceeded:
				return backoff.Permanent(perr)
			default:
				// This could check if error is a non-temporary
				// `net.Error`, but continuing to retry as long
				// as the host claims that it is available
				// at that address, is probably ok?
			}
			return perr
		}

		return nil
	}, bctx)

	if err != nil {
		mgr.logger.Warn("failed to connect to peer, not retrying",
			"err", err,
			"node_id", node.ID,
		)
	}
}

func publicKeyToPeerID(pk signature.PublicKey) (core.PeerID, error) {
	pubKey, err := publicKeyToPubKey(pk)
	if err != nil {
		return "", err
	}

	id, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	return id, nil
}

func nodeToAddrInfo(node *node.Node) (*peer.AddrInfo, error) {
	var (
		ai  peer.AddrInfo
		err error
	)
	if ai.ID, err = publicKeyToPeerID(node.P2P.ID); err != nil {
		return nil, fmt.Errorf("failed to extract public key from node P2P ID: %w", err)
	}
	for _, nodeAddr := range node.P2P.Addresses {
		addr, err := manet.FromNetAddr(&nodeAddr.TCPAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to libp2p format: %w", err)
		}
		ai.Addrs = append(ai.Addrs, addr)
	}

	return &ai, nil
}
