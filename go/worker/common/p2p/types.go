package p2p

import (
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	roothash "github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
)

// TxnSchedulerBatchDispatchSigCtx is the context used for signing
// transaction scheduler batch dispatch messages.
var TxnSchedulerBatchDispatchSigCtx = []byte("EkTscBat")

// NOTE: Bump CommitteeProtocol version in go/common/version if you
//       change any of the structures below.

// Message is a message sent to nodes via P2P transport.
type Message struct {
	_struct struct{} `codec:",omitempty"` // nolint

	// RuntimeID is the identifier of the runtime this message
	// belongs to. It is used as a namespace.
	RuntimeID signature.PublicKey `codec:"runtime_id"`

	// GroupVersion is the version of all elected committees (the consensus
	// block height of last processed committee election). Messages with
	// non-matching group versions will be discarded.
	GroupVersion int64 `codec:"group_version"`

	// Jaeger's span context in binary format.
	SpanContext []byte `codec:"span"`

	// Message types.

	Ack   *Ack
	Error *Error

	SignedTxnSchedulerBatchDispatch *SignedTxnSchedulerBatchDispatch
	ComputeWorkerFinished           *ComputeWorkerFinished
}

// TxnSchedulerBatchDispatch is the message sent from the transaction
// scheduler to compute workers after a batch is ready to be computed.
type TxnSchedulerBatchDispatch struct {
	// TODO: Txn scheduler should explicitly sign the message (#1790).

	// CommitteeID is the committee ID of the target compute committee.
	CommitteeID hash.Hash `codec:"cid"`

	// IORoot is the I/O root containing the inputs (transactions) that
	// the compute node should use.
	IORoot hash.Hash `codec:"io_root"`

	// StorageSignatures are the storage receipt signatures for the I/O root.
	StorageSignatures []signature.Signature `codec:"storage_signatures"`

	// Header is the block header on which the batch should be
	// based.
	Header roothash.Header `codec:"header"`
}

// SignedTxnSchedulerBatchDispatch is a TxnSchedulerBatchDispatch, signed by
// the transaction scheduler.
type SignedTxnSchedulerBatchDispatch struct {
	signature.Signed
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (t *TxnSchedulerBatchDispatch) MarshalCBOR() []byte {
	return cbor.Marshal(t)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (t *TxnSchedulerBatchDispatch) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, t)
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedTxnSchedulerBatchDispatch) Open(tsbd *TxnSchedulerBatchDispatch) error {
	return s.Signed.Open(TxnSchedulerBatchDispatchSigCtx, tsbd)
}

// SignTxnSchedulerBatchDispatch signs a TxnSchedulerBatchDispatch struct
// using the given signer.
func SignTxnSchedulerBatchDispatch(signer signature.Signer, tsbd *TxnSchedulerBatchDispatch) (*SignedTxnSchedulerBatchDispatch, error) {
	signed, err := signature.SignSigned(signer, TxnSchedulerBatchDispatchSigCtx, tsbd)
	if err != nil {
		return nil, err
	}

	return &SignedTxnSchedulerBatchDispatch{
		Signed: *signed,
	}, nil
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
