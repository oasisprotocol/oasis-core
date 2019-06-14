package p2p

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	roothash "github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
)

// NOTE: Bump CommitteeProtocol version in go/common/version if you
//       change any of the structures below.

// Message is a message sent to nodes via P2P transport.
type Message struct {
	_struct struct{} `codec:",omitempty"` // nolint

	// RuntimeID is the identifier of the runtime this message
	// belongs to. It is used as a namespace.
	RuntimeID signature.PublicKey `codec:"runtime_id"`

	// GroupHash is the hash identifying the group this message
	// is from/to. Messages with non-matching group hashes will
	// be discarded.
	GroupHash hash.Hash `codec:"group_hash"`

	// Jaeger's span context in binary format.
	SpanContext []byte `codec:"span"`

	Ack   *Ack
	Error *Error

	// Batch dispatch.
	TxnSchedulerBatchDispatch *TxnSchedulerBatchDispatch
	ComputeWorkerFinished     *ComputeWorkerFinished
}

// TxnSchedulerBatchDispatch is the message sent from the transaction
// scheduler to compute workers after a batch is ready to be computed.
type TxnSchedulerBatchDispatch struct {
	// TODO: Txn scheduler should explicitly sign the message (#1790).

	// IORoot is the I/O root containing the inputs (transactions) that
	// the compute node should use.
	IORoot hash.Hash `codec:"io_root"`

	// StorageReceipt is the storage receipt for the I/O root.
	StorageReceipt signature.Signature `codec:"storage_receipt"`

	// Header is the block header on which the batch should be
	// based.
	Header roothash.Header `codec:"header"`
}

// ComputeWorkerFinished is the message sent from the compute workers to
// the merge committee after a batch has been processed and is ready to
// be merged.
type ComputeWorkerFinished struct {
	// Commitment is a compute worker commitment.
	Commitment commitment.ComputeCommitment
}

// Ack is an acknowledgement that a message was received.
type Ack struct {
}

// Error is an error response.
type Error struct {
	// Message is an error message.
	Message string
}
