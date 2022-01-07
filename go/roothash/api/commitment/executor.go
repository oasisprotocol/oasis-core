// Package commitment defines a roothash commitment.
package commitment

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

var (
	// ExecutorSignatureContext is the signature context used to sign executor
	// worker commitments.
	ExecutorSignatureContext = signature.NewContext(
		"oasis-core/roothash: executor commitment",
		signature.WithChainSeparation(),
		signature.WithDynamicSuffix(" for runtime ", common.NamespaceHexSize),
	)

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
	Round        uint64    `json:"round"`
	PreviousHash hash.Hash `json:"previous_hash"`

	// Optional fields (may be absent for failure indication).

	IORoot       *hash.Hash `json:"io_root,omitempty"`
	StateRoot    *hash.Hash `json:"state_root,omitempty"`
	MessagesHash *hash.Hash `json:"messages_hash,omitempty"`

	// InMessagesHash is the hash of processed incoming messages.
	InMessagesHash *hash.Hash `json:"in_msgs_hash,omitempty"`
	// InMessagesCount is the number of processed incoming messages.
	InMessagesCount uint32 `json:"in_msgs_count,omitempty"`
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

// ExecutorCommitmentFailure is the executor commitment failure reason.
type ExecutorCommitmentFailure uint8

const (
	// FailureNone indicates that no failure has occurred.
	FailureNone ExecutorCommitmentFailure = 0
	// FailureUnknown indicates a generic failure.
	FailureUnknown ExecutorCommitmentFailure = 1
	// FailureStateUnavailable indicates that batch processing failed due to the state being
	// unavailable.
	FailureStateUnavailable ExecutorCommitmentFailure = 2
)

// ExecutorCommitmentHeader is the header of an executor commitment.
type ExecutorCommitmentHeader struct {
	ComputeResultsHeader

	Failure ExecutorCommitmentFailure `json:"failure,omitempty"`

	// Optional fields (may be absent for failure indication).

	RAKSignature *signature.RawSignature `json:"rak_sig,omitempty"`
}

// SetFailure sets failure reason and clears any fields that should be clear
// in a failure indicating commitment.
func (eh *ExecutorCommitmentHeader) SetFailure(failure ExecutorCommitmentFailure) {
	eh.ComputeResultsHeader.IORoot = nil
	eh.ComputeResultsHeader.StateRoot = nil
	eh.ComputeResultsHeader.MessagesHash = nil
	eh.ComputeResultsHeader.InMessagesHash = nil
	eh.ComputeResultsHeader.InMessagesCount = 0
	eh.RAKSignature = nil
	eh.Failure = failure
}

// Sign signs the executor commitment header.
func (eh *ExecutorCommitmentHeader) Sign(signer signature.Signer, runtimeID common.Namespace) (*signature.RawSignature, error) {
	sigCtx, err := ExecutorSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return nil, fmt.Errorf("signature context error: %w", err)
	}

	signature, err := signature.Sign(signer, sigCtx, cbor.Marshal(eh))
	if err != nil {
		return nil, err
	}
	return &signature.Signature, nil
}

// VerifyRAK verifies the RAK signature.
func (eh *ExecutorCommitmentHeader) VerifyRAK(rak signature.PublicKey) error {
	if eh.RAKSignature == nil {
		return fmt.Errorf("missing RAK signature")
	}
	if !rak.Verify(ComputeResultsHeaderSignatureContext, cbor.Marshal(eh.ComputeResultsHeader), eh.RAKSignature[:]) {
		return fmt.Errorf("RAK signature verification failed")
	}
	return nil
}

// MostlyEqual compares against another executor commitment header for equality.
//
// The RAKSignature field is not compared.
func (eh *ExecutorCommitmentHeader) MostlyEqual(other *ExecutorCommitmentHeader) bool {
	if eh.Failure != other.Failure {
		return false
	}
	h1 := eh.ComputeResultsHeader.EncodedHash()
	h2 := other.ComputeResultsHeader.EncodedHash()
	return h1.Equal(&h2)
}

// ExecutorCommitment is a commitment to results of processing a proposed runtime block.
type ExecutorCommitment struct {
	// NodeID is the public key of the node that generated this commitment.
	NodeID signature.PublicKey `json:"node_id"`

	// Header is the commitment header.
	Header ExecutorCommitmentHeader `json:"header"`

	// Signature is the commitment header signature.
	Signature signature.RawSignature `json:"sig"`

	// Messages are the messages emitted by the runtime.
	//
	// This field is only present in case this commitment belongs to the proposer. In case of
	// the commitment being submitted as equivocation evidence, this field should be omitted.
	Messages []message.Message `json:"messages,omitempty"`
}

// Sign signs the executor commitment header and sets the signature on the commitment.
func (c *ExecutorCommitment) Sign(signer signature.Signer, runtimeID common.Namespace) error {
	if !c.NodeID.Equal(signer.Public()) {
		return fmt.Errorf("node ID does not match signer (ID: %s signer: %s)", c.NodeID, signer.Public())
	}

	sig, err := c.Header.Sign(signer, runtimeID)
	if err != nil {
		return err
	}
	c.Signature = *sig
	return nil
}

// Verify verifies that the header signature is valid.
func (c *ExecutorCommitment) Verify(runtimeID common.Namespace) error {
	sigCtx, err := ExecutorSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return fmt.Errorf("roothash/commitment: signature context error: %w", err)
	}

	if !c.NodeID.Verify(sigCtx, cbor.Marshal(c.Header), c.Signature[:]) {
		return fmt.Errorf("roothash/commitment: signature verification failed")
	}
	return nil
}

// ValidateBasic performs basic executor commitment validity checks.
func (c *ExecutorCommitment) ValidateBasic() error {
	header := &c.Header.ComputeResultsHeader
	switch c.Header.Failure {
	case FailureNone:
		// Ensure header fields are present.
		if header.IORoot == nil {
			return fmt.Errorf("missing IORoot")
		}
		if header.StateRoot == nil {
			return fmt.Errorf("missing StateRoot")
		}
		if header.MessagesHash == nil {
			return fmt.Errorf("missing messages hash")
		}
		if header.InMessagesHash == nil {
			return fmt.Errorf("missing incoming messages hash")
		}

		// Validate any included runtime messages.
		for i, msg := range c.Messages {
			if err := msg.ValidateBasic(); err != nil {
				return fmt.Errorf("bad runtime message %d: %w", i, err)
			}
		}
	case FailureUnknown, FailureStateUnavailable:
		// Ensure header fields are empty.
		if header.IORoot != nil {
			return fmt.Errorf("failure indicating body includes IORoot")
		}
		if header.StateRoot != nil {
			return fmt.Errorf("failure indicating commitment includes StateRoot")
		}
		if header.MessagesHash != nil {
			return fmt.Errorf("failure indicating commitment includes MessagesHash")
		}
		if header.InMessagesHash != nil || header.InMessagesCount != 0 {
			return fmt.Errorf("failure indicating commitment includes InMessagesHash/Count")
		}
		// In case of failure indicating commitment make sure RAK signature is empty.
		if c.Header.RAKSignature != nil {
			return fmt.Errorf("failure indicating body includes RAK signature")
		}
		// In case of failure indicating commitment make sure messages are empty.
		if len(c.Messages) > 0 {
			return fmt.Errorf("failure indicating body includes messages")
		}
	default:
		return fmt.Errorf("invalid failure: %d", c.Header.Failure)
	}

	return nil
}

// MostlyEqual returns true if the commitment is mostly equal to another
// specified commitment as per discrepancy detection criteria.
func (c *ExecutorCommitment) MostlyEqual(other OpenCommitment) bool {
	h := c.Header.ComputeResultsHeader.EncodedHash()
	otherHash := other.(*ExecutorCommitment).Header.ComputeResultsHeader.EncodedHash()
	return h.Equal(&otherHash)
}

// IsIndicatingFailure returns true if this commitment indicates a failure.
func (c *ExecutorCommitment) IsIndicatingFailure() bool {
	return c.Header.Failure != FailureNone
}

// ToVote returns a hash that represents a vote for this commitment as
// per discrepancy resolution criteria.
func (c *ExecutorCommitment) ToVote() hash.Hash {
	return c.Header.ComputeResultsHeader.EncodedHash()
}

// ToDDResult returns a commitment-specific result after discrepancy
// detection.
func (c *ExecutorCommitment) ToDDResult() interface{} {
	return c
}
