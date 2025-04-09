package p2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// nopP2P is a no-op peer-to-peer node that does not propagate anything.
type nopP2P struct{}

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
func (p *nopP2P) GetStatus() *api.Status {
	return nil
}

// Implements api.Service.
func (p *nopP2P) Addresses() []node.Address {
	return nil
}

// Implements api.Service.
func (p *nopP2P) Peers(common.Namespace) []string {
	return nil
}

// Implements api.Service.
func (p *nopP2P) Publish(context.Context, string, any) {
}

// Implements api.Service.
func (p *nopP2P) RegisterHandler(string, api.Handler) {
}

// Implements api.Service.
func (p *nopP2P) BlockPeer(core.PeerID) {
}

// Implements api.Service.
func (p *nopP2P) Host() core.Host {
	return nil
}

// Implements api.Service.
func (p *nopP2P) PeerManager() api.PeerManager {
	return nil
}

// Implements api.Service.
func (p *nopP2P) RegisterProtocol(core.ProtocolID, int, int) {
}

// Implements api.Service.
func (p *nopP2P) RegisterProtocolServer(rpc.Server) {
}

// Implements api.Service.
func (p *nopP2P) GetMinRepublishInterval() time.Duration {
	return time.Hour
}

// NewNop creates a new no-op P2P node.
func NewNop() api.Service {
	return &nopP2P{}
}
