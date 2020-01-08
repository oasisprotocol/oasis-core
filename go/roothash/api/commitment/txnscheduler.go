package commitment

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
)

// TxnSchedulerBatchDispatchSigCtx is the context used for signing
// transaction scheduler batch dispatch messages.
var TxnSchedulerBatchDispatchSigCtx = signature.NewContext("oasis-core/roothash: tx batch dispatch", signature.WithChainSeparation())

// TxnSchedulerBatchDispatch is the message sent from the transaction
// scheduler to executor workers after a batch is ready to be executed.
//
// Don't forget to bump CommitteeProtocol version in go/common/version
// if you change anything in this struct.
type TxnSchedulerBatchDispatch struct {
	// CommitteeID is the committee ID of the target executor committee.
	CommitteeID hash.Hash `json:"cid"`

	// IORoot is the I/O root containing the inputs (transactions) that
	// the executor node should use.
	IORoot hash.Hash `json:"io_root"`

	// StorageSignatures are the storage receipt signatures for the I/O root.
	StorageSignatures []signature.Signature `json:"storage_signatures"`

	// Header is the block header on which the batch should be based.
	Header block.Header `json:"header"`
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
