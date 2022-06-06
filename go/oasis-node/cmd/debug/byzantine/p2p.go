package byzantine

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/api"
)

type p2pReqRes struct {
	peerID     signature.PublicKey
	msg        interface{}
	responseCh chan<- error
}

type p2pHandle struct {
	service  p2pAPI.Service
	requests chan p2pReqRes
}

func newP2PHandle() *p2pHandle {
	return &p2pHandle{
		requests: make(chan p2pReqRes),
	}
}

type txMsgHandler struct {
	target *p2pHandle
}

func (h *txMsgHandler) DecodeMessage(msg []byte) (interface{}, error) {
	var tx []byte
	if err := cbor.Unmarshal(msg, &tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func (h *txMsgHandler) AuthorizeMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}) error {
	// Everyone is allowed to publish transactions.
	return nil
}

func (h *txMsgHandler) HandleMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}, isOwn bool) error {
	if isOwn {
		return nil
	}
	responseCh := make(chan error)
	h.target.requests <- p2pReqRes{
		peerID:     peerID,
		msg:        msg,
		responseCh: responseCh,
	}
	return <-responseCh
}

type committeeMsgHandler struct {
	target *p2pHandle
}

func (h *committeeMsgHandler) DecodeMessage(msg []byte) (interface{}, error) {
	var dec p2pAPI.CommitteeMessage
	if err := cbor.Unmarshal(msg, &dec); err != nil {
		return nil, err
	}
	return &dec, nil
}

func (h *committeeMsgHandler) AuthorizeMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}) error {
	// The Byzantine node itself isn't especially robust. We assume that
	// the other nodes are honest.
	return nil
}

func (h *committeeMsgHandler) HandleMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}, isOwn bool) error {
	if isOwn {
		return nil
	}
	responseCh := make(chan error)
	h.target.requests <- p2pReqRes{
		peerID:     peerID,
		msg:        msg,
		responseCh: responseCh,
	}
	return <-responseCh
}

func (ph *p2pHandle) start(ht *honestTendermint, id *identity.Identity, runtimeID common.Namespace) error {
	if ph.service != nil {
		return fmt.Errorf("P2P service already started")
	}

	var err error
	ph.service, err = p2p.New(id, ht.service)
	if err != nil {
		return fmt.Errorf("P2P service New: %w", err)
	}

	ph.service.RegisterHandler(runtimeID, p2pAPI.TopicKindTx, &txMsgHandler{ph})
	ph.service.RegisterHandler(runtimeID, p2pAPI.TopicKindCommittee, &committeeMsgHandler{ph})

	return nil
}

func (ph *p2pHandle) stop() error {
	if ph.service == nil {
		return fmt.Errorf("P2P service not started")
	}

	ph.service.Stop()
	ph.service = nil

	return nil
}

func init() {
	p2p.DebugForceAllowUnroutableAddresses()
}
