package p2p

import (
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	executor "github.com/oasisprotocol/oasis-core/go/worker/compute/executor/api"
)

// NOTE: Bump CommitteeProtocol version in go/common/version if you
//       change any of the structures below.

// Message is a message sent to nodes via P2P transport.
type Message struct {
	// GroupVersion is the version of all elected committees (the consensus
	// block height of last processed committee election). Messages with
	// non-matching group versions will be discarded.
	GroupVersion int64 `json:"group_version,omitempty"`

	Proposal       *commitment.Proposal           `json:",omitempty"`
	ExecutorCommit *commitment.ExecutorCommitment `json:",omitempty"`
	Tx             *executor.Tx                   `json:",omitempty"`
}
