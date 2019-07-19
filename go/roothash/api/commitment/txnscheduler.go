// Package commitment defines a roothash commitment.
package commitment

import (
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
)

// TxnSchedulerBatchDispatchSigCtx is the context used for signing
// transaction scheduler batch dispatch messages.
var TxnSchedulerBatchDispatchSigCtx = []byte("EkTscBat")

// TxnSchedulerBatchDispatch is the message sent from the transaction
// scheduler to compute workers after a batch is ready to be computed.
//
// Don't forget to bump CommitteeProtocol version in go/common/version
// if you change anything in this struct.
type TxnSchedulerBatchDispatch struct {
	// CommitteeID is the committee ID of the target compute committee.
	CommitteeID hash.Hash `codec:"cid"`

	// IORoot is the I/O root containing the inputs (transactions) that
	// the compute node should use.
	IORoot hash.Hash `codec:"io_root"`

	// StorageSignatures are the storage receipt signatures for the I/O root.
	StorageSignatures []signature.Signature `codec:"storage_signatures"`

	// Header is the block header on which the batch should be
	// based.
	Header block.Header `codec:"header"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (t *TxnSchedulerBatchDispatch) MarshalCBOR() []byte {
	return cbor.Marshal(t)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (t *TxnSchedulerBatchDispatch) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, t)
}
