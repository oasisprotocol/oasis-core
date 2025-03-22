// Package p2p implements the Oasis Core libp2p backed light client provider.
package p2p

import (
	"context"
	"errors"
	"fmt"
	"sync"

	cmtlightprovider "github.com/cometbft/cometbft/light/provider"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/p2p/light"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// LightClientProvidersPool manages a pool of light client providers.
//
// Pool ensures that that every instantiated provider is backed by a single distinct libp2p peer
// at all times.
type LightClientProvidersPool struct {
	ctx context.Context

	chainID string

	p2pMgr rpc.PeerManager
	rc     rpc.Client

	l            sync.Mutex
	peerRegistry map[core.PeerID]bool
}

// NewLightClientProviderPool returns a light client provider pool.
func NewLightClientProviderPool(ctx context.Context, chainContext string, chainID string, p2p rpc.P2P) *LightClientProvidersPool {
	pid := light.ProtocolID(chainContext)

	mgr := rpc.NewPeerManager(p2p, pid)
	rc := rpc.NewClient(p2p.Host(), pid)
	rc.RegisterListener(mgr)

	return &LightClientProvidersPool{
		ctx:          ctx,
		chainID:      chainID,
		peerRegistry: make(map[core.PeerID]bool),
		p2pMgr:       mgr,
		rc:           rc,
	}
}

// NewLightClientProvider creates a new provider for the CometBFT's light client backed by the
// Oasis Core LightBlocks P2P protocol.
//
// Each instantiated provider is backed by a distinct P2P Peer.
func (p *LightClientProvidersPool) NewLightClientProvider() *LightClientProvider {
	provider := &LightClientProvider{
		initCh:    make(chan struct{}),
		chainID:   p.chainID,
		p2pMgr:    p.p2pMgr,
		rc:        p.rc,
		refreshCh: make(chan struct{}, 1),
		logger:    logging.GetLogger("cometbft/light/p2p"),
		pool:      p,
	}

	go provider.worker(p.ctx)

	return provider
}

type LightClientProvider struct {
	initOnce sync.Once
	initCh   chan struct{}

	logger *logging.Logger

	chainID string

	p2pMgr rpc.PeerManager
	rc     rpc.Client

	refreshCh chan struct{}

	// Guarded by lock.
	l      sync.RWMutex
	peerID *core.PeerID

	pool *LightClientProvidersPool
}

func (lp *LightClientProvider) worker(ctx context.Context) {
	ch, sub, err := lp.p2pMgr.WatchUpdates()
	if err != nil {
		lp.logger.Error("peer manager watch updates failure", "err", err)
		return
	}
	defer sub.Close()

	lp.refreshPeer()

	for {
		select {
		case <-lp.refreshCh:
			// Explicitly requested peer refresh.
			lp.refreshPeer()
		case update := <-ch:
			peerID := lp.getPeer()
			switch {
			case peerID == nil:
				// If we have no peer and update was received try obtaining a peer.
				lp.refreshPeer()
			default:
				// If we have a peer, ensure it was not removed.
				if update.ID != *peerID {
					continue
				}
				if update.PeerRemoved == nil {
					continue
				}
				// Peer was removed, try obtaining a new peer.
				lp.refreshPeer()
			}
		case <-ctx.Done():
			lp.dropPeer()
			return
		}
	}
}

func (lp *LightClientProvider) dropPeer() {
	lp.l.Lock()
	defer lp.l.Unlock()
	lp.pool.l.Lock()
	defer lp.pool.l.Unlock()
	// Remove peer from pool.
	if lp.peerID != nil {
		delete(lp.pool.peerRegistry, *lp.peerID)
	}
	lp.peerID = nil
}

func (lp *LightClientProvider) getPeer() *core.PeerID {
	lp.l.RLock()
	defer lp.l.RUnlock()
	return lp.peerID
}

func (lp *LightClientProvider) refreshPeer() {
	lp.l.Lock()
	defer lp.l.Unlock()
	lp.pool.l.Lock()
	defer lp.pool.l.Unlock()

	lp.logger.Debug("refreshing peer", "peer", lp.peerID)

	// Remove selected peer.
	if lp.peerID != nil {
		delete(lp.pool.peerRegistry, *lp.peerID)
	}
	lp.peerID = nil

	// Select new peer.
	peers := lp.p2pMgr.GetBestPeers()
	for _, peerID := range peers {
		if _, found := lp.pool.peerRegistry[peerID]; found {
			continue
		}
		lp.logger.Debug("peer obtained", "peer_id", peerID)
		p := peerID
		lp.peerID = &p
		lp.pool.peerRegistry[peerID] = true
		lp.initOnce.Do(func() {
			close(lp.initCh)
		})
		return
	}
	lp.logger.Debug("no p2p peer available")
}

// Initialized implements api.Provider.
func (lp *LightClientProvider) Initialized() <-chan struct{} {
	return lp.initCh
}

// PeerID implements api.Provider.
func (lp *LightClientProvider) PeerID() string {
	peer := lp.getPeer()
	if peer == nil {
		// This happens if a provider is not yet initialized, or
		// (less likely) if a peer was just dropped and no new peer is available.
		return ""
	}
	return peer.String()
}

// RefreshPeer implements api.Provider.
func (lp *LightClientProvider) RefreshPeer() {
	select {
	case lp.refreshCh <- struct{}{}:
	default:
	}
}

// MalevolentProvider implements api.Provider.
func (lp *LightClientProvider) MalevolentProvider(peerID string) {
	lp.p2pMgr.RecordBadPeer(core.PeerID(peerID))
}

// ReportEvidence implements api.Provider.
func (lp *LightClientProvider) ReportEvidence(ctx context.Context, ev cmttypes.Evidence) error {
	proto, err := cmttypes.EvidenceToProto(ev)
	if err != nil {
		return fmt.Errorf("failed to convert evidence: %w", err)
	}
	meta, err := proto.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	_, err = lp.SubmitEvidence(ctx, &consensus.Evidence{Meta: meta})
	return err
}

// SubmitEvidence implements api.Provider.
func (lp *LightClientProvider) SubmitEvidence(ctx context.Context, evidence *consensus.Evidence) (rpc.PeerFeedback, error) {
	peerID := lp.getPeer()
	if peerID == nil {
		return nil, fmt.Errorf("no peer available")
	}

	pf, err := lp.rc.Call(ctx, *peerID, light.MethodSubmitEvidence, evidence, nil)
	if err != nil {
		return nil, err
	}

	return pf, nil
}

// GetStoredLightBlock implements api.Provider.
func (lp *LightClientProvider) GetStoredLightBlock(_ int64) (*consensus.LightBlock, error) {
	// The remote client provider stores no blocks locally.
	return nil, consensus.ErrVersionNotFound
}

// GetLightBlock implements api.Provider.
func (lp *LightClientProvider) GetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, rpc.PeerFeedback, error) {
	peerID := lp.getPeer()
	if peerID == nil {
		return nil, nil, consensus.ErrVersionNotFound
	}

	var rsp consensus.LightBlock
	pf, err := lp.rc.Call(ctx, *peerID, light.MethodGetLightBlock, height, &rsp)
	if err != nil {
		return nil, nil, err
	}

	// Ensure peer returned the block for the queried height.
	if rsp.Height != height {
		pf.RecordBadPeer()
		return nil, nil, consensus.ErrVersionNotFound
	}

	return &rsp, pf, nil
}

// GetParameters implements api.Provider.
func (lp *LightClientProvider) GetParameters(ctx context.Context, height int64) (*consensus.Parameters, rpc.PeerFeedback, error) {
	peerID := lp.getPeer()
	if peerID == nil {
		return nil, nil, consensus.ErrVersionNotFound
	}

	var rsp consensus.Parameters
	pf, err := lp.rc.Call(ctx, *peerID, light.MethodGetParameters, height, &rsp)
	if err != nil {
		return nil, nil, err
	}

	// Ensure peer returned the parameters for the queried height.
	if rsp.Height != height {
		pf.RecordBadPeer()
		return nil, nil, consensus.ErrVersionNotFound
	}

	return &rsp, pf, nil
}

// ChainID implements api.Provider.
func (lp *LightClientProvider) ChainID() string {
	return lp.chainID
}

// LightBlock implements api.Provider.
func (lp *LightClientProvider) LightBlock(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	lb, _, err := lp.LightBlockWithPeerID(ctx, height)
	return lb, err
}

// LightBlockWithPeerID implements api.Provider.
func (lp *LightClientProvider) LightBlockWithPeerID(ctx context.Context, height int64) (*cmttypes.LightBlock, string, error) {
	rsp, pf, err := lp.GetLightBlock(ctx, height)
	switch {
	case err == nil:
	case errors.Is(err, consensus.ErrVersionNotFound):
		return nil, "", cmtlightprovider.ErrLightBlockNotFound
	default:
		return nil, "", cmtlightprovider.ErrNoResponse
	}

	// Decode CometBFT-specific light block.
	var protoLb cmtproto.LightBlock
	if err = protoLb.Unmarshal(rsp.Meta); err != nil {
		pf.RecordBadPeer()
		return nil, "", cmtlightprovider.ErrNoResponse
	}
	tlb, err := cmttypes.LightBlockFromProto(&protoLb)
	if err != nil {
		pf.RecordBadPeer()
		return nil, "", cmtlightprovider.ErrNoResponse
	}
	if err = tlb.ValidateBasic(lp.chainID); err != nil {
		pf.RecordFailure()
		return nil, "", cmtlightprovider.ErrNoResponse
	}

	return tlb, string(pf.PeerID()), nil
}
