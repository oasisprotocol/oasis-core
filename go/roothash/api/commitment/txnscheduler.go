package commitment

import (
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
)

// TxnSchedulerBatchDispatchSigCtx is the context used for signing
// transaction scheduler batch dispatch messages.
var TxnSchedulerBatchDispatchSigCtx = signature.NewContext("EkTscBat")

// TxnSchedulerBatchDispatch is the message sent from the transaction
// scheduler to compute workers after a batch is ready to be computed.
//
// Don't forget to bump CommitteeProtocol version in go/common/version
// if you change anything in this struct.
type TxnSchedulerBatchDispatch struct {
	// CommitteeID is the committee ID of the target compute committee.
	CommitteeID hash.Hash `json:"cid"`

	// IORoot is the I/O root containing the inputs (transactions) that
	// the compute node should use.
	IORoot hash.Hash `json:"io_root"`

	// StorageSignatures are the storage receipt signatures for the I/O root.
	StorageSignatures []signature.Signature `json:"storage_signatures"`

	// Header is the block header on which the batch should be based.
	Header block.Header `json:"header"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (t *TxnSchedulerBatchDispatch) MarshalCBOR() []byte {
	return cbor.Marshal(t)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (t *TxnSchedulerBatchDispatch) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, t)
}

// SignedTxnSchedulerBatchDispatch is a TxnSchedulerBatchDispatch, signed by
// the transaction scheduler.
type SignedTxnSchedulerBatchDispatch struct {
	signature.Signed
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
