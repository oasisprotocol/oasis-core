package byzantine

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
)

var _ p2p.Handler = (*p2pRecvHandler)(nil)

type p2pReqRes struct {
	peerID     signature.PublicKey
	msg        *p2p.Message
	responseCh chan<- error
}

type p2pHandle struct {
	context  context.Context
	cancel   context.CancelFunc
	service  *p2p.P2P
	requests chan p2pReqRes
}

func newP2PHandle() *p2pHandle {
	return &p2pHandle{
		requests: make(chan p2pReqRes),
	}
}

// p2pRecvHandler forwards requests to, and responses from, a goroutine.
type p2pRecvHandler struct {
	target *p2pHandle
}

// IsPeerAuthorized implements p2p Handler.
func (h *p2pRecvHandler) IsPeerAuthorized(peerID signature.PublicKey) bool {
	// The Byzantine node itself isn't especially robust. We assume that
	// the other nodes are honest.
	return true
}

// HandlePeerMessage implements p2p Handler.
func (h *p2pRecvHandler) HandlePeerMessage(peerID signature.PublicKey, msg *p2p.Message) error {
	responseCh := make(chan error)
	h.target.requests <- p2pReqRes{
		peerID:     peerID,
		msg:        msg,
		responseCh: responseCh,
	}
	return <-responseCh
}

func (ph *p2pHandle) start(id *identity.Identity, runtimeID signature.PublicKey) error {
	if ph.service != nil {
		return errors.New("P2P service already started")
	}

	ph.context, ph.cancel = context.WithCancel(context.Background())
	var err error
	ph.service, err = p2p.New(ph.context, id)
	if err != nil {
		return errors.Wrap(err, "P2P service New")
	}

	ph.service.RegisterHandler(runtimeID, &p2pRecvHandler{
		target: ph,
	})

	return nil
}

func (ph *p2pHandle) stop() error {
	if ph.service == nil {
		return errors.New("P2P service not started")
	}

	ph.cancel()
	ph.service = nil
	ph.context = nil
	ph.cancel = nil

	return nil
}

func init() {
	p2p.DebugForceAllowUnroutableAddresses()
}
