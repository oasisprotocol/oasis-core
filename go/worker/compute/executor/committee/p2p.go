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

func (h *committeeMsgHandler) AuthorizeMessage(_ context.Context, peerID signature.PublicKey, msg interface{}) error {
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

	if _, ok := committee.Peers[peerID]; !ok {
		return p2pError.Permanent(fmt.Errorf("peer is not authorized to publish committee messages"))
	}
	return nil
}

func (h *committeeMsgHandler) HandleMessage(_ context.Context, _ signature.PublicKey, msg interface{}, isOwn bool) error {
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

		// Before opening the signed dispatch message, verify that it was actually signed by one
		// of the transaction schedulers.
		committee := epoch.GetExecutorCommittee().Committee
		rank, ok := committee.SchedulerRank(proposal.Header.Round, proposal.NodeID)
		if !ok {
			// Invalid scheduler, do not forward.
			return p2pError.Permanent(errMsgFromNonTxnSched)
		}

		// Transaction scheduler checks out, verify signature.
		if err := proposal.Verify(h.n.commonNode.Runtime.ID()); err != nil {
			return p2pError.Permanent(err)
		}

		h.n.logger.Debug("received a proposal",
			"runtime_id", h.n.commonNode.Runtime.ID(),
			"round", proposal.Header.Round,
			"node_id", proposal.NodeID,
			"rank", rank,
			"batch_size", len(proposal.Batch),
		)

		// Add to the queue.
		if err := h.n.proposals.Add(proposal, rank); err != nil {
			return err
		}

		// Notify the worker about the new proposal.
		h.n.reselect()

		return nil
	default:
		return p2pError.ErrUnhandledMessage
	}
}
