package committee

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	p2pError "github.com/oasisprotocol/oasis-core/go/p2p/error"
)

type committeeMsgHandler struct {
	n *Node
}

func (h *committeeMsgHandler) DecodeMessage(msg []byte) (interface{}, error) {
	var dec p2p.CommitteeMessage
	if err := cbor.Unmarshal(msg, &dec); err != nil {
		return nil, err
	}
	return &dec, nil
}

func (h *committeeMsgHandler) AuthorizeMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}) error {
	cm := msg.(*p2p.CommitteeMessage) // Ensured by DecodeMessage.

	epoch := h.n.commonNode.Group.GetEpochSnapshot()
	if !epoch.IsValid() {
		return fmt.Errorf("epoch is not yet known")
	}

	switch now := epoch.GetEpochNumber(); {
	case cm.Epoch == now:
	case cm.Epoch < now:
		// Past messages will never become valid.
		return p2pError.Permanent(fmt.Errorf("epoch in the past"))
	case cm.Epoch > now+1:
		// Messages too far off should be dropped.
		return p2pError.Permanent(fmt.Errorf("epoch in the future"))
	case cm.Epoch > now:
		// Future messages may become valid.
		return fmt.Errorf("epoch in the future")
	}

	// Only known committee members are allowed to submit messages on this topic.
	committee := epoch.GetExecutorCommittee()
	if committee == nil {
		return fmt.Errorf("executor committee is not yet known")
	}

	if !committee.Peers[peerID] {
		return p2pError.Permanent(fmt.Errorf("peer is not authorized to publish committee messages"))
	}
	return nil
}

func (h *committeeMsgHandler) HandleMessage(ctx context.Context, peerID signature.PublicKey, msg interface{}, isOwn bool) error {
	cm := msg.(*p2p.CommitteeMessage) // Ensured by DecodeMessage.

	switch {
	case cm.Proposal != nil:
		// Ignore own messages as those are handled separately.
		if isOwn {
			return nil
		}
		crash.Here(crashPointBatchReceiveAfter)

		proposal := cm.Proposal

		epoch := h.n.commonNode.Group.GetEpochSnapshot()
		h.n.commonNode.CrossNode.Lock()
		round := h.n.commonNode.CurrentBlock.Header.Round
		h.n.commonNode.CrossNode.Unlock()

		// Before opening the signed dispatch message, verify that it was actually signed by the
		// current transaction scheduler.
		if err := epoch.VerifyTxnSchedulerSigner(proposal.NodeID, round); err != nil {
			// Not signed by the current txn scheduler.
			return errMsgFromNonTxnSched
		}

		// Transaction scheduler checks out, verify signature.
		if err := proposal.Verify(h.n.commonNode.Runtime.ID()); err != nil {
			return p2pError.Permanent(err)
		}

		err := h.n.queueBatchBlocking(ctx, proposal)
		if err != nil {
			return err
		}
		return nil
	default:
		return p2pError.ErrUnhandledMessage
	}
}

// HandlePeerTx implements NodeHooks.
func (n *Node) HandlePeerTx(ctx context.Context, tx []byte) error {
	// Nothing to do here.
	return nil
}
