// Package commitment defines a roothash commitment.
package commitment

import (
	"bytes"
	"errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

var (
	// ComputeSignatureContext is the signature context used to sign compute
	// worker commitments.
	ComputeSignatureContext = signature.NewContext("oasis-core/roothash: compute commitment", signature.WithChainSeparation())

	// ComputeResultsHeaderSignatureContext is the signature context used to
	// sign compute results headers with RAK.
	ComputeResultsHeaderSignatureContext = signature.NewContext("oasis-core/roothash: compute results header")
)

// ComputeResultsHeader is the header of a computed batch output by a runtime. This
// header is a compressed representation (e.g., hashes instead of full content) of
// the actual results.
//
// These headers are signed by RAK inside the runtime and included in compute
// commitments.
//
// Keep the roothash RAK validation in sync with changes to this structure.
type ComputeResultsHeader struct {
	PreviousHash hash.Hash        `json:"previous_hash"`
	IORoot       hash.Hash        `json:"io_root"`
	StateRoot    hash.Hash        `json:"state_root"`
	Messages     []*block.Message `json:"messages"`
}

// IsParentOf returns true iff the header is the parent of a child header.
func (h *ComputeResultsHeader) IsParentOf(child *block.Header) bool {
	childHash := child.EncodedHash()
	return h.PreviousHash.Equal(&childHash)
}

// EncodedHash returns the encoded cryptographic hash of the header.
func (h *ComputeResultsHeader) EncodedHash() hash.Hash {
	var hh hash.Hash

	hh.From(h)

	return hh
}

// ComputeBody holds the data signed in a compute worker commitment.
type ComputeBody struct {
	CommitteeID       hash.Hash              `json:"cid"`
	Header            ComputeResultsHeader   `json:"header"`
	StorageSignatures []signature.Signature  `json:"storage_signatures"`
	RakSig            signature.RawSignature `json:"rak_sig"`

	TxnSchedSig      signature.Signature   `json:"txn_sched_sig"`
	InputRoot        hash.Hash             `json:"input_root"`
	InputStorageSigs []signature.Signature `json:"input_storage_sigs"`
}

// VerifyTxnSchedSignature rebuilds the batch dispatch message from the data
// in the ComputeBody struct and verifies if the txn scheduler signature
// matches what we're seeing.
func (m *ComputeBody) VerifyTxnSchedSignature(header block.Header) bool {
	dispatch := &TxnSchedulerBatchDispatch{
		CommitteeID:       m.CommitteeID,
		IORoot:            m.InputRoot,
		StorageSignatures: m.InputStorageSigs,
		Header:            header,
	}

	return m.TxnSchedSig.Verify(TxnSchedulerBatchDispatchSigCtx, cbor.Marshal(dispatch))
}

// RootsForStorageReceipt gets the merkle roots that must be part of
// a storage receipt.
func (m *ComputeBody) RootsForStorageReceipt() []hash.Hash {
	return []hash.Hash{
		m.Header.IORoot,
		m.Header.StateRoot,
	}
}

// VerifyStorageReceiptSignature validates that the storage receipt signatures
// match the signatures for the current merkle roots.
//
// Note: Ensuring that the signature is signed by the keypair(s) that are
// expected is the responsibility of the caller.
func (m *ComputeBody) VerifyStorageReceiptSignatures(ns common.Namespace, round uint64) error {
	receiptBody := storage.ReceiptBody{
		Version:   1,
		Namespace: ns,
		Round:     round,
		Roots:     m.RootsForStorageReceipt(),
	}

	if !signature.VerifyManyToOne(storage.ReceiptSignatureContext, cbor.Marshal(receiptBody), m.StorageSignatures) {
		return signature.ErrVerifyFailed
	}

	return nil
}

// VerifyStorageReceipt validates that the provided storage receipt
// matches the header.
func (m *ComputeBody) VerifyStorageReceipt(ns common.Namespace, round uint64, receipt *storage.ReceiptBody) error {
	if !receipt.Namespace.Equal(&ns) {
		return errors.New("roothash: receipt has unexpected namespace")
	}

	if receipt.Round != round {
		return errors.New("roothash: receipt has unexpected round")
	}

	roots := m.RootsForStorageReceipt()
	if len(receipt.Roots) != len(roots) {
		return errors.New("roothash: receipt has unexpected number of roots")
	}

	for idx, v := range roots {
		if !bytes.Equal(v[:], receipt.Roots[idx][:]) {
			return errors.New("roothash: receipt has unexpected roots")
		}
	}

	return nil
}

// ComputeCommitment is a roothash commitment from a compute worker.
//
// The signed content is ComputeBody.
type ComputeCommitment struct {
	signature.Signed
}

// OpenComputeCommitment is a compute commitment that has been verified and
// deserialized.
//
// The open commitment still contains the original signed commitment.
type OpenComputeCommitment struct {
	ComputeCommitment

	Body *ComputeBody `json:"body"`
}

// MostlyEqual returns true if the commitment is mostly equal to another
// specified commitment as per discrepancy detection criteria.
func (c OpenComputeCommitment) MostlyEqual(other OpenCommitment) bool {
	h := c.Body.Header.EncodedHash()
	otherHash := other.(OpenComputeCommitment).Body.Header.EncodedHash()
	return h.Equal(&otherHash)
}

// ToVote returns a hash that represents a vote for this commitment as
// per discrepancy resolution criteria.
func (c OpenComputeCommitment) ToVote() hash.Hash {
	return c.Body.Header.EncodedHash()
}

// ToDDResult returns a commitment-specific result after discrepancy
// detection.
func (c OpenComputeCommitment) ToDDResult() interface{} {
	return c.Body.Header
}

// Open validates the compute commitment signature, and de-serializes the message.
// This does not validate the RAK signature.
func (c *ComputeCommitment) Open() (*OpenComputeCommitment, error) {
	var body ComputeBody
	if err := c.Signed.Open(ComputeSignatureContext, &body); err != nil {
		return nil, errors.New("roothash/commitment: commitment has invalid signature")
	}

	return &OpenComputeCommitment{
		ComputeCommitment: *c,
		Body:              &body,
	}, nil
}

// SignComputeCommitment serializes the message and signs the commitment.
func SignComputeCommitment(signer signature.Signer, body *ComputeBody) (*ComputeCommitment, error) {
	signed, err := signature.SignSigned(signer, ComputeSignatureContext, body)
	if err != nil {
		return nil, err
	}

	return &ComputeCommitment{
		Signed: *signed,
	}, nil
}
