package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/rpc"
)

// nopP2P is a no-op peer-to-peer node that does not propagate anything.
type nopP2P struct{}

// Implements api.Service.
func (*nopP2P) SetNodeImportance(kind api.ImportanceKind, runtimeID common.Namespace, p2pIDs map[signature.PublicKey]bool) {
}

// Implements api.Service.
func (p *nopP2P) Cleanup() {
}

// Implements api.Service.
func (p *nopP2P) Name() string {
	return "no-op p2p"
}

// Implements api.Service.
func (p *nopP2P) Start() error {
	return nil
}

// Implements api.Service.
func (p *nopP2P) Stop() {
}

// Implements api.Service.
func (p *nopP2P) Quit() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Implements api.Service.
func (p *nopP2P) Addresses() []node.Address {
	return nil
}

// Implements api.Service.
func (p *nopP2P) Peers(runtimeID common.Namespace) []string {
	return nil
}

// Implements api.Service.
func (p *nopP2P) PublishCommittee(ctx context.Context, runtimeID common.Namespace, msg *api.CommitteeMessage) {
}

// Implements api.Service.
func (p *nopP2P) PublishTx(ctx context.Context, runtimeID common.Namespace, msg api.TxMessage) {
}

// Implements api.Service.
func (p *nopP2P) RegisterHandler(runtimeID common.Namespace, kind api.TopicKind, handler api.Handler) {
}

// Implements api.Service.
func (p *nopP2P) BlockPeer(peerID core.PeerID) {
}

// Implements api.Service.
func (p *nopP2P) GetHost() core.Host {
	return nil
}

// Implements api.Service.
func (p *nopP2P) RegisterProtocolServer(srv rpc.Server) {
}

// Implements api.Service.
func (p *nopP2P) GetMinRepublishInterval() time.Duration {
	return time.Hour
}

// NewNop creates a new no-op P2P node.
func NewNop() api.Service {
	return &nopP2P{}
}
