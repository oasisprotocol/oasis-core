package byzantine

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/p2p"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
)

type p2pReqRes struct {
	peerID     signature.PublicKey
	msg        any
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

func (h *txMsgHandler) DecodeMessage(msg []byte) (any, error) {
	var tx []byte
	if err := cbor.Unmarshal(msg, &tx); err != nil {
		return nil, err
	}
	return tx, nil
}

func (h *txMsgHandler) AuthorizeMessage(context.Context, signature.PublicKey, any) error {
	// Everyone is allowed to publish transactions.
	return nil
}

func (h *txMsgHandler) HandleMessage(_ context.Context, peerID signature.PublicKey, msg any, isOwn bool) error {
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

func (h *committeeMsgHandler) DecodeMessage(msg []byte) (any, error) {
	var dec p2pAPI.CommitteeMessage
	if err := cbor.Unmarshal(msg, &dec); err != nil {
		return nil, err
	}
	return &dec, nil
}

func (h *committeeMsgHandler) AuthorizeMessage(context.Context, signature.PublicKey, any) error {
	// The Byzantine node itself isn't especially robust. We assume that
	// the other nodes are honest.
	return nil
}

func (h *committeeMsgHandler) HandleMessage(_ context.Context, peerID signature.PublicKey, msg any, isOwn bool) error {
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

func (ph *p2pHandle) start(ht *honestCometBFT, id *identity.Identity, chainContext string, runtimeID common.Namespace) error {
	if ph.service != nil {
		return fmt.Errorf("P2P service already started")
	}

	var err error
	ph.service, err = p2p.New(id, chainContext, nil)
	if err != nil {
		return fmt.Errorf("P2P service New: %w", err)
	}
	if err := ph.service.PeerManager().PeerRegistry().RegisterConsensus(chainContext, ht.service); err != nil {
		return fmt.Errorf("failed to register consensus with peer registry: %w", err)
	}

	txTopic := protocol.NewTopicKindTxID(chainContext, runtimeID)
	ph.service.RegisterHandler(txTopic, &txMsgHandler{ph})

	committeeTopic := protocol.NewTopicKindCommitteeID(chainContext, runtimeID)
	ph.service.RegisterHandler(committeeTopic, &committeeMsgHandler{ph})

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
