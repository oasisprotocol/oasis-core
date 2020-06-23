package p2p

import "github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"

// NOTE: Bump CommitteeProtocol version in go/common/version if you
//       change any of the structures below.

// Message is a message sent to nodes via P2P transport.
type Message struct {
	// GroupVersion is the version of all elected committees (the consensus
	// block height of last processed committee election). Messages with
	// non-matching group versions will be discarded.
	GroupVersion int64 `json:"group_version,omitempty"`

	// Jaeger's span context in binary format.
	SpanContext []byte `json:"span,omitempty"`

	TxnSchedulerBatch *commitment.SignedTxnSchedulerBatch `json:",omitempty"`
	ExecutorCommit    *commitment.ExecutorCommitment      `json:",omitempty"`
}
