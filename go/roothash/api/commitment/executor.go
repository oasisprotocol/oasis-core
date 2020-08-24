// Package commitment defines a roothash commitment.
package commitment

import (
	"bytes"
	"errors"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

var (
	// ExecutorSignatureContext is the signature context used to sign executor
	// worker commitments.
	ExecutorSignatureContext = signature.NewContext("oasis-core/roothash: executor commitment", signature.WithChainSeparation())

	// ComputeResultsHeaderSignatureContext is the signature context used to
	// sign compute results headers with RAK.
	ComputeResultsHeaderSignatureContext = signature.NewContext("oasis-core/roothash: compute results header")
)

// ComputeResultsHeader is the header of a computed batch output by a runtime. This
// header is a compressed representation (e.g., hashes instead of full content) of
// the actual results.
//
// These headers are signed by RAK inside the runtime and included in executor
// commitments.
//
// Keep the roothash RAK validation in sync with changes to this structure.
type ComputeResultsHeader struct {
	Round        uint64           `json:"round"`
	PreviousHash hash.Hash        `json:"previous_hash"`
	IORoot       hash.Hash        `json:"io_root"`
	StateRoot    hash.Hash        `json:"state_root"`
	Messages     []*block.Message `json:"messages"`
}

// IsParentOf returns true iff the header is the parent of a child header.
func (h *ComputeResultsHeader) IsParentOf(child *block.Header) bool {
	if h.Round != child.Round+1 {
		return false
	}

	childHash := child.EncodedHash()
	return h.PreviousHash.Equal(&childHash)
}

// EncodedHash returns the encoded cryptographic hash of the header.
func (h *ComputeResultsHeader) EncodedHash() hash.Hash {
	return hash.NewFrom(h)
}

// ComputeBody holds the data signed in a compute worker commitment.
type ComputeBody struct {
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
	dispatch := &ProposedBatch{
		IORoot:            m.InputRoot,
		StorageSignatures: m.InputStorageSigs,
		Header:            header,
	}

	return m.TxnSchedSig.Verify(ProposedBatchSignatureContext, cbor.Marshal(dispatch))
}

// RootsForStorageReceipt gets the merkle roots that must be part of
// a storage receipt.
func (m *ComputeBody) RootsForStorageReceipt() []hash.Hash {
	return []hash.Hash{
		m.Header.IORoot,
		m.Header.StateRoot,
	}
}

// VerifyStorageReceiptSignatures validates that the storage receipt signatures
// match the signatures for the current merkle roots.
//
// Note: Ensuring that the signature is signed by the keypair(s) that are
// expected is the responsibility of the caller.
func (m *ComputeBody) VerifyStorageReceiptSignatures(ns common.Namespace) error {
	receiptBody := storage.ReceiptBody{
		Version:   1,
		Namespace: ns,
		Round:     m.Header.Round,
		Roots:     m.RootsForStorageReceipt(),
	}

	if !signature.VerifyManyToOne(storage.ReceiptSignatureContext, cbor.Marshal(receiptBody), m.StorageSignatures) {
		return signature.ErrVerifyFailed
	}

	return nil
}

// VerifyStorageReceipt validates that the provided storage receipt
// matches the header.
func (m *ComputeBody) VerifyStorageReceipt(ns common.Namespace, receipt *storage.ReceiptBody) error {
	if !receipt.Namespace.Equal(&ns) {
		return errors.New("roothash: receipt has unexpected namespace")
	}

	if receipt.Round != m.Header.Round {
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

// ExecutorCommitment is a roothash commitment from an executor worker.
//
// The signed content is ComputeBody.
type ExecutorCommitment struct {
	signature.Signed
}

// Equal compares vs another ExecutorCommitment for equality.
func (c *ExecutorCommitment) Equal(cmp *ExecutorCommitment) bool {
	return c.Signed.Equal(&cmp.Signed)
}

// OpenExecutorCommitment is an executor commitment that has been verified and
// deserialized.
//
// The open commitment still contains the original signed commitment.
type OpenExecutorCommitment struct {
	ExecutorCommitment

	Body *ComputeBody `json:"-"` // No need to serialize as it can be reconstructed.
}

// UnmarshalCBOR handles CBOR unmarshalling from passed data.
func (c *OpenExecutorCommitment) UnmarshalCBOR(data []byte) error {
	if err := cbor.Unmarshal(data, &c.ExecutorCommitment); err != nil {
		return err
	}

	c.Body = new(ComputeBody)
	return cbor.Unmarshal(c.Blob, c.Body)
}

// MostlyEqual returns true if the commitment is mostly equal to another
// specified commitment as per discrepancy detection criteria.
func (c OpenExecutorCommitment) MostlyEqual(other OpenCommitment) bool {
	h := c.Body.Header.EncodedHash()
	otherHash := other.(OpenExecutorCommitment).Body.Header.EncodedHash()
	return h.Equal(&otherHash)
}

// ToVote returns a hash that represents a vote for this commitment as
// per discrepancy resolution criteria.
func (c OpenExecutorCommitment) ToVote() hash.Hash {
	return c.Body.Header.EncodedHash()
}

// ToDDResult returns a commitment-specific result after discrepancy
// detection.
func (c OpenExecutorCommitment) ToDDResult() interface{} {
	return c.Body.Header
}

// Open validates the executor commitment signature, and de-serializes the message.
// This does not validate the RAK signature.
func (c *ExecutorCommitment) Open() (*OpenExecutorCommitment, error) {
	var body ComputeBody
	if err := c.Signed.Open(ExecutorSignatureContext, &body); err != nil {
		return nil, errors.New("roothash/commitment: commitment has invalid signature")
	}

	return &OpenExecutorCommitment{
		ExecutorCommitment: *c,
		Body:               &body,
	}, nil
}

// SignExecutorCommitment serializes the message and signs the commitment.
func SignExecutorCommitment(signer signature.Signer, body *ComputeBody) (*ExecutorCommitment, error) {
	signed, err := signature.SignSigned(signer, ExecutorSignatureContext, body)
	if err != nil {
		return nil, err
	}

	return &ExecutorCommitment{
		Signed: *signed,
	}, nil
}
