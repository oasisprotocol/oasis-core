package committee

import (
	"fmt"

	"github.com/google/btree"

	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
)

// maxPendingProposals is the maximum number of pending proposals that can be queued.
const maxPendingProposals = 16

// pendingProposals is a priority queue of pending proposals, ordered by round.
type pendingProposals struct {
	q *btree.BTreeG[*unresolvedBatch]
}

func proposalLessFunc(a, b *unresolvedBatch) bool {
	return a.proposal.Header.Round < b.proposal.Header.Round
}

func newPendingProposals() *pendingProposals {
	return &pendingProposals{
		q: btree.NewG(2, proposalLessFunc),
	}
}

// addPendingProposalLocked adds a new pending proposal that MUST HAVE already undergone basic
// validity checks and is therefore considered a valid proposal for the given round, but the node's
// local consensus view may not yet be ready to process the proposal.
//
// Must be called with the n.commonNode.CrossNode lock held.
func (n *Node) addPendingProposalLocked(batch *unresolvedBatch) error {
	currentRound := n.commonNode.CurrentBlock.Header.Round
	round := batch.proposal.Header.Round

	// Drop any past proposals.
	if round <= currentRound {
		return p2pError.Permanent(fmt.Errorf("proposal round is in the past")) // Do not forward.
	}

	n.pendingProposals.q.ReplaceOrInsert(batch)

	// In case of overflows, remove the round that is the most in the future.
	n.prunePendingProposalsLocked()
	if n.pendingProposals.q.Len() >= maxPendingProposals {
		removed, _ := n.pendingProposals.q.DeleteMax()
		if removed == batch {
			return p2pError.Permanent(fmt.Errorf("proposal queue overflow")) // Do not forward.
		}
	}

	return nil
}

// prunePendingProposalsLocked prunes any proposals which are not valid anymore.
//
// Must be called with the n.commonNode.CrossNode lock held.
func (n *Node) prunePendingProposalsLocked() {
	currentRound := n.commonNode.CurrentBlock.Header.Round

	for {
		batch, ok := n.pendingProposals.q.Min()
		if !ok {
			break
		}
		if batch.proposal.Header.Round > currentRound {
			// All further proposals are valid.
			break
		}

		// Remove invalid proposals.
		n.pendingProposals.q.DeleteMin()
	}
}

// handlePendingProposalsLocked attempts to handle any pending proposals. At most one proposal is
// handled.
//
// Must be called with the n.commonNode.CrossNode lock held.
func (n *Node) handlePendingProposalsLocked() {
	// Prune any invalid pending proposals.
	n.prunePendingProposalsLocked()

	// Dequeue the next proposal.
	batch, ok := n.pendingProposals.q.DeleteMin()
	if !ok {
		return
	}

	// Ignoring the error is fine, because the proposal is either handled (no error) or added
	// back to the queue (no error since an overflow cannot happen given we just removed it).
	// Since we checked above that the proposal is valid there is no other option.
	_ = n.handleProposalLocked(batch)
}
