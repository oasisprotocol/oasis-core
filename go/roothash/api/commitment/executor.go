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
	// Round is the round number.
	Round uint64 `json:"round"`

	// PreviousHash is the hash of the previous block header this batch was computed against.
	PreviousHash hash.Hash `json:"previous_hash"`

	// Optional fields (may be absent for failure indication).

	// IORoot is the I/O merkle root.
	IORoot *hash.Hash `json:"io_root,omitempty"`
	// StateRoot is the root hash of the state after computing this batch.
	StateRoot *hash.Hash `json:"state_root,omitempty"`
	// MessagesHash is the hash of messages sent from this batch.
	MessagesHash *hash.Hash `json:"messages_hash,omitempty"`

	// InMessagesHash is hash of processed incoming messages.
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
	// SchedulerID is the public key of the node that scheduled transactions
	// and prepared the proposal.
	SchedulerID signature.PublicKey `json:"scheduler_id"`

	// Header is the compute results header.
	Header ComputeResultsHeader `json:"header"`

	// Failure is the executor commitment failure reason.
	Failure ExecutorCommitmentFailure `json:"failure,omitempty"`

	// Optional fields (may be absent for failure indication).

	RAKSignature *signature.RawSignature `json:"rak_sig,omitempty"`
}

// SetFailure sets failure reason and clears any fields that should be clear
// in a failure indicating commitment.
func (eh *ExecutorCommitmentHeader) SetFailure(failure ExecutorCommitmentFailure) {
	eh.Header.IORoot = nil
	eh.Header.StateRoot = nil
	eh.Header.MessagesHash = nil
	eh.Header.InMessagesHash = nil
	eh.Header.InMessagesCount = 0
	eh.RAKSignature = nil
	eh.Failure = failure
}

// Sign signs the executor commitment header.
func (eh *ExecutorCommitmentHeader) Sign(signer signature.Signer, runtimeID common.Namespace) (*signature.RawSignature, error) {
	sigCtx, err := ExecutorSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return nil, fmt.Errorf("signature context error: %w", err)
	}

	return signature.SignRaw(signer, sigCtx, cbor.Marshal(eh))
}

// VerifyRAK verifies the RAK signature.
func (eh *ExecutorCommitmentHeader) VerifyRAK(rak signature.PublicKey) error {
	if eh.RAKSignature == nil {
		return fmt.Errorf("missing RAK signature")
	}
	if !rak.Verify(ComputeResultsHeaderSignatureContext, cbor.Marshal(eh.Header), eh.RAKSignature[:]) {
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
	h1 := eh.Header.EncodedHash()
	h2 := other.Header.EncodedHash()
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
	header := &c.Header.Header
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
	h := c.ToVote()
	otherH := other.ToVote()
	return h.Equal(&otherH)
}

// IsIndicatingFailure returns true if this commitment indicates a failure.
func (c *ExecutorCommitment) IsIndicatingFailure() bool {
	return c.Header.Failure != FailureNone
}

// ToVote returns a hash that represents a vote for this commitment as
// per discrepancy resolution criteria.
func (c *ExecutorCommitment) ToVote() hash.Hash {
	return c.Header.Header.EncodedHash()
}

// ToDDResult returns a commitment-specific result after discrepancy
// detection.
func (c *ExecutorCommitment) ToDDResult() interface{} {
	return c
}
