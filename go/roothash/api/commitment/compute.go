// Package commitment defines a roothash commitment.
package commitment

import (
	"bytes"
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

var (
	// ComputeSignatureContext is the signature context used to sign compute
	// worker commitments.
	ComputeSignatureContext = []byte("EkCommCC")

	// ComputeResultsHeaderSignatureContext is the signature context used to
	// sign compute results headers with RAK.
	ComputeResultsHeaderSignatureContext = []byte("EkComRHd")
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
	PreviousHash hash.Hash `codec:"previous_hash"`
	IORoot       hash.Hash `codec:"io_root"`
	StateRoot    hash.Hash `codec:"state_root"`
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

// MarshalCBOR serializes the type into a CBOR byte vector.
func (h *ComputeResultsHeader) MarshalCBOR() []byte {
	return cbor.Marshal(h)
}

// UnmarshalCBOR decodes a CBOR marshaled compute results header.
func (h *ComputeResultsHeader) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, h)
}

// ComputeBody holds the data signed in a compute worker commitment.
type ComputeBody struct {
	CommitteeID    hash.Hash              `codec:"cid"`
	Header         ComputeResultsHeader   `codec:"header"`
	StorageReceipt signature.Signature    `codec:"storage_receipt"`
	RakSig         signature.RawSignature `codec:"rak_sig"`
}

// RootsForStorageReceipt gets the merkle roots that must be part of
// a storage receipt.
func (m *ComputeBody) RootsForStorageReceipt() []hash.Hash {
	return []hash.Hash{
		m.Header.IORoot,
		m.Header.StateRoot,
	}
}

// VerifyStorageReceiptSignature validates that the storage receipt
// signature matches the hashes.
//
// Note: Ensuring that the signature is signed by the keypair that is
// expected is the responsibility of the caller.
func (m *ComputeBody) VerifyStorageReceiptSignature() error {
	receipt := storage.MKVSReceiptBody{
		Version: 1,
		Roots:   m.RootsForStorageReceipt(),
	}

	signed := signature.Signed{
		Blob:      receipt.MarshalCBOR(),
		Signature: m.StorageReceipt,
	}

	var check storage.MKVSReceipt
	return signed.Open(storage.MKVSReceiptSignatureContext, &check)
}

// VerifyStorageReceipt validates that the provided storage receipt
// matches the header.
func (m *ComputeBody) VerifyStorageReceipt(receipt *storage.MKVSReceiptBody) error {
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

// MarshalCBOR serializes the type into a CBOR byte vector.
func (m *ComputeBody) MarshalCBOR() []byte {
	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes a CBOR marshaled message.
func (m *ComputeBody) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, m)
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

	Body *ComputeBody `codec:"body"`
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
func SignComputeCommitment(privateKey signature.PrivateKey, body *ComputeBody) (*ComputeCommitment, error) {
	signed, err := signature.SignSigned(privateKey, ComputeSignatureContext, body)
	if err != nil {
		return nil, err
	}

	return &ComputeCommitment{
		Signed: *signed,
	}, nil
}

func init() {
	cbor.RegisterType(OpenComputeCommitment{}, "com.oasislabs/OpenComputeCommitment")
}
