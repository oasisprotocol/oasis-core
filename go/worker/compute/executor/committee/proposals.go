package committee

import (
	"fmt"
	"sync"

	"github.com/google/btree"

	p2pError "github.com/oasisprotocol/oasis-core/go/p2p/error"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

// maxPendingProposals is the maximum number of pending proposals that can be queued.
const maxPendingProposals = 32

type proposalInfo struct {
	proposal *commitment.Proposal
	rank     uint64
}

// proposalQueue is a priority queue of pending proposals, ordered by round and rank.
type proposalQueue struct {
	l sync.RWMutex

	q *btree.BTreeG[*proposalInfo]

	round uint64
}

func proposalLessFunc(a, b *proposalInfo) bool {
	if a.proposal.Header.Round == b.proposal.Header.Round {
		return a.rank < b.rank
	}
	return a.proposal.Header.Round < b.proposal.Header.Round
}

func newPendingProposals() *proposalQueue {
	return &proposalQueue{
		q: btree.NewG(2, proposalLessFunc),
	}
}

// Best returns the best proposal for the given round with rank within given bounds.
func (q *proposalQueue) Best(round uint64, minRank uint64, maxRank uint64, exclude map[uint64]struct{}) (*commitment.Proposal, uint64, bool) {
	q.l.RLock()
	defer q.l.RUnlock()

	var (
		proposal *commitment.Proposal
		rank     uint64
		ok       bool
	)

	q.q.Ascend(func(pi *proposalInfo) bool {
		switch {
		case pi.proposal.Header.Round < round:
			return true
		case pi.proposal.Header.Round > round:
			return false
		case pi.rank < minRank:
			return true
		case pi.rank > maxRank:
			return false
		default:
			if _, skip := exclude[pi.rank]; skip {
				return true
			}
			proposal = pi.proposal
			rank = pi.rank
			ok = true
			return false
		}
	})

	return proposal, rank, ok
}

// Add adds a new pending proposal that MUST HAVE already undergone basic validity checks
// and is therefore considered a valid proposal for the given round, but the node's
// local consensus view may not yet be ready to process the proposal.
func (q *proposalQueue) Add(proposal *commitment.Proposal, rank uint64) error {
	q.l.Lock()
	defer q.l.Unlock()

	// Drop any past proposals.
	if proposal.Header.Round < q.round {
		return p2pError.Permanent(fmt.Errorf("proposal round is in the past")) // Do not forward.
	}

	info := proposalInfo{
		proposal: proposal,
		rank:     rank,
	}
	q.q.ReplaceOrInsert(&info)

	// In case of overflows, remove the proposal that is the most in the future.
	if q.q.Len() <= maxPendingProposals {
		return nil
	}
	removed, _ := q.q.DeleteMax()
	if removed == &info {
		return fmt.Errorf("proposal queue overflow")
	}

	return nil
}

// Prune prunes any proposals which are not valid anymore.
func (q *proposalQueue) Prune(round uint64) {
	q.l.Lock()
	defer q.l.Unlock()

	for {
		info, ok := q.q.Min()
		if !ok {
			break
		}
		if info.proposal.Header.Round >= round {
			// All further proposals are valid.
			break
		}

		// Remove invalid proposals.
		q.q.DeleteMin()
	}

	q.round = round
}
