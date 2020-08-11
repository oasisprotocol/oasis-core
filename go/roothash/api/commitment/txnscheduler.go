package commitment

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// TxnSchedulerBatchSigCtx is the context used for signing
// transaction scheduler batch dispatch messages.
var TxnSchedulerBatchSigCtx = signature.NewContext("oasis-core/roothash: tx batch", signature.WithChainSeparation())

// TxnSchedulerBatch is the message sent from the transaction scheduler
// to executor workers after a batch is ready to be executed.
//
// Don't forget to bump CommitteeProtocol version in go/common/version
// if you change anything in this struct.
type TxnSchedulerBatch struct {
	// IORoot is the I/O root containing the inputs (transactions) that
	// the executor node should use.
	IORoot hash.Hash `json:"io_root"`

	// StorageSignatures are the storage receipt signatures for the I/O root.
	StorageSignatures []signature.Signature `json:"storage_signatures"`

	// Header is the block header on which the batch should be based.
	Header block.Header `json:"header"`
}

// SignedTxnSchedulerBatch is a TxnSchedulerBatch, signed by
// the transaction scheduler.
type SignedTxnSchedulerBatch struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedTxnSchedulerBatch) Open(tsbd *TxnSchedulerBatch) error {
	return s.Signed.Open(TxnSchedulerBatchSigCtx, tsbd)
}

// SignTxnSchedulerBatch signs a TxnSchedulerBatch struct using the
// given signer.
func SignTxnSchedulerBatch(signer signature.Signer, tsbd *TxnSchedulerBatch) (*SignedTxnSchedulerBatch, error) {
	signed, err := signature.SignSigned(signer, TxnSchedulerBatchSigCtx, tsbd)
	if err != nil {
		return nil, err
	}

	return &SignedTxnSchedulerBatch{
		Signed: *signed,
	}, nil
}
