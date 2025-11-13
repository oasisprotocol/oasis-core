package light

import (
	"context"
	"errors"
	"fmt"
	"sync"

	cmtlightprovider "github.com/cometbft/cometbft/light/provider"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmtAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/p2p/light"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// ProviderPool manages a pool of light client providers.
//
// Pool ensures that that every instantiated provider is backed by a single distinct libp2p peer
// at all times.
type ProviderPool struct {
	ctx context.Context

	chainID string

	p2pMgr rpc.PeerManager
	rc     rpc.Client

	l            sync.Mutex
	peerRegistry map[core.PeerID]bool
}

// NewProviderPool returns a light client provider pool.
func NewProviderPool(ctx context.Context, chainContext string, p2p rpc.P2P) *ProviderPool {
	chainID := cmtAPI.CometBFTChainID(chainContext)
	pid := light.ProtocolID(chainContext)

	mgr := rpc.NewPeerManager(p2p, pid)
	rc := rpc.NewClient(p2p.Host(), pid)
	rc.RegisterListener(mgr)

	return &ProviderPool{
		ctx:          ctx,
		chainID:      chainID,
		peerRegistry: make(map[core.PeerID]bool),
		p2pMgr:       mgr,
		rc:           rc,
	}
}

// NewProvider creates a new provider for the CometBFT's light client backed by the
// Oasis Core LightBlocks P2P protocol.
//
// Each instantiated provider is backed by a distinct P2P Peer.
func (p *ProviderPool) NewProvider() *Provider {
	provider := &Provider{
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

type Provider struct {
	logger *logging.Logger

	chainID string

	p2pMgr rpc.PeerManager
	rc     rpc.Client

	refreshCh chan struct{}

	// Guarded by lock.
	l      sync.RWMutex
	peerID *core.PeerID

	pool *ProviderPool
}

func (p *Provider) worker(ctx context.Context) {
	ch, sub, err := p.p2pMgr.WatchUpdates()
	if err != nil {
		p.logger.Error("peer manager watch updates failure", "err", err)
		return
	}
	defer sub.Close()

	p.refreshPeer()

	for {
		select {
		case <-p.refreshCh:
			// Explicitly requested peer refresh.
			p.refreshPeer()
		case update := <-ch:
			peerID := p.getPeer()
			switch {
			case peerID == nil:
				// If we have no peer and update was received try obtaining a peer.
				p.refreshPeer()
			default:
				// If we have a peer, ensure it was not removed.
				if update.ID != *peerID {
					continue
				}
				if update.PeerRemoved == nil {
					continue
				}
				// Peer was removed, try obtaining a new peer.
				p.refreshPeer()
			}
		case <-ctx.Done():
			p.dropPeer()
			return
		}
	}
}

func (p *Provider) dropPeer() {
	p.l.Lock()
	defer p.l.Unlock()
	p.pool.l.Lock()
	defer p.pool.l.Unlock()
	// Remove peer from pool.
	if p.peerID != nil {
		delete(p.pool.peerRegistry, *p.peerID)
	}
	p.peerID = nil
}

func (p *Provider) getPeer() *core.PeerID {
	p.l.RLock()
	defer p.l.RUnlock()
	return p.peerID
}

func (p *Provider) refreshPeer() {
	p.l.Lock()
	defer p.l.Unlock()
	p.pool.l.Lock()
	defer p.pool.l.Unlock()

	p.logger.Debug("refreshing peer", "peer", p.peerID)

	// Remove selected peer.
	if p.peerID != nil {
		delete(p.pool.peerRegistry, *p.peerID)
	}
	p.peerID = nil

	// Select new peer.
	peers := p.p2pMgr.GetBestPeers()
	for _, peerID := range peers {
		if _, found := p.pool.peerRegistry[peerID]; found {
			continue
		}
		p.logger.Debug("peer obtained", "peer_id", peerID)
		pid := peerID
		p.peerID = &pid
		p.pool.peerRegistry[peerID] = true
		return
	}
	p.logger.Debug("no p2p peer available")
}

// PeerID implements api.Provider.
func (p *Provider) PeerID() string {
	peer := p.getPeer()
	if peer == nil {
		// This happens if a provider is not yet initialized, or
		// (less likely) if a peer was just dropped and no new peer is available.
		return ""
	}
	return peer.String()
}

// RefreshPeer implements api.Provider.
func (p *Provider) RefreshPeer() {
	select {
	case p.refreshCh <- struct{}{}:
	default:
	}
}

// MalevolentProvider implements api.Provider.
func (p *Provider) MalevolentProvider(peerID string) {
	p.p2pMgr.RecordBadPeer(core.PeerID(peerID))
}

// ReportEvidence implements api.Provider.
func (p *Provider) ReportEvidence(ctx context.Context, ev cmttypes.Evidence) error {
	proto, err := cmttypes.EvidenceToProto(ev)
	if err != nil {
		return fmt.Errorf("failed to convert evidence: %w", err)
	}
	meta, err := proto.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	_, err = p.SubmitEvidence(ctx, &consensus.Evidence{Meta: meta})
	return err
}

// SubmitEvidence implements api.Provider.
func (p *Provider) SubmitEvidence(ctx context.Context, evidence *consensus.Evidence) (rpc.PeerFeedback, error) {
	peerID := p.getPeer()
	if peerID == nil {
		return nil, fmt.Errorf("no peer available")
	}

	pf, err := p.rc.Call(ctx, *peerID, light.MethodSubmitEvidence, evidence, nil)
	if err != nil {
		return nil, err
	}

	return pf, nil
}

// GetStoredLightBlock implements api.Provider.
func (p *Provider) GetStoredLightBlock(int64) (*consensus.LightBlock, error) {
	// The remote client provider stores no blocks locally.
	return nil, consensus.ErrVersionNotFound
}

type lightBlock struct {
	lb  *consensus.LightBlock
	clb *cmttypes.LightBlock
}

func (p *Provider) getLightBlock(ctx context.Context, height int64) (*lightBlock, rpc.PeerFeedback, error) {
	peerID := p.getPeer()
	if peerID == nil {
		return nil, nil, consensus.ErrVersionNotFound
	}

	var lb consensus.LightBlock
	pf, err := p.rc.Call(ctx, *peerID, light.MethodGetLightBlock, height, &lb)
	if err != nil {
		return nil, nil, err
	}

	if lb.Height != height {
		pf.RecordBadPeer()
		return nil, nil, consensus.ErrVersionNotFound
	}

	clb, err := DecodeLightBlock(&lb)
	if err != nil {
		pf.RecordBadPeer()
		return nil, nil, err
	}
	if err = clb.ValidateBasic(p.chainID); err != nil {
		pf.RecordFailure()
		return nil, nil, err
	}

	rsp := &lightBlock{
		lb:  &lb,
		clb: clb,
	}

	return rsp, pf, nil
}

func (p *Provider) getValidators(ctx context.Context, height int64) (*consensus.Validators, rpc.PeerFeedback, error) {
	peerID := p.getPeer()
	if peerID == nil {
		return nil, nil, consensus.ErrVersionNotFound
	}

	var validators consensus.Validators
	pf, err := p.rc.Call(ctx, *peerID, light.MethodGetValidators, height, &validators)
	if err != nil {
		return nil, nil, err
	}

	if validators.Height != height {
		pf.RecordBadPeer()
		return nil, nil, consensus.ErrVersionNotFound
	}

	if _, err = DecodeValidators(&validators); err != nil {
		pf.RecordBadPeer()
		return nil, nil, fmt.Errorf("corrupted validators: %w", err)
	}

	return &validators, pf, nil
}

func (p *Provider) getParameters(ctx context.Context, height int64) (*consensus.Parameters, rpc.PeerFeedback, error) {
	peerID := p.getPeer()
	if peerID == nil {
		return nil, nil, consensus.ErrVersionNotFound
	}

	var rsp consensus.Parameters
	pf, err := p.rc.Call(ctx, *peerID, light.MethodGetParameters, height, &rsp)
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
func (p *Provider) ChainID() string {
	return p.chainID
}

// LightBlock implements api.Provider.
func (p *Provider) LightBlock(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	lb, _, err := p.LightBlockWithPeerID(ctx, height)
	return lb, err
}

// LightBlockWithPeerID implements api.Provider.
func (p *Provider) LightBlockWithPeerID(ctx context.Context, height int64) (*cmttypes.LightBlock, string, error) {
	rsp, pf, err := p.getLightBlock(ctx, height)
	if err != nil {
		if errors.Is(err, consensus.ErrVersionNotFound) {
			return nil, "", cmtlightprovider.ErrLightBlockNotFound
		}
		return nil, "", cmtlightprovider.ErrNoResponse
	}
	return rsp.clb, string(pf.PeerID()), nil
}
