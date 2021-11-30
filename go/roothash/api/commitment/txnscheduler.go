package commitment

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// ProposalSignatureContext is the context used for signing propose batch dispatch messages.
var ProposalSignatureContext = signature.NewContext(
	"oasis-core/roothash: proposal",
	signature.WithChainSeparation(),
	signature.WithDynamicSuffix(" for runtime ", common.NamespaceHexSize),
)

// ProposalHeader is the header of the batch proposal.
type ProposalHeader struct {
	// Round is the proposed round number.
	Round uint64 `json:"round"`

	// PreviousHash is the hash of the block header on which the batch should be based.
	PreviousHash hash.Hash `json:"previous_hash"`

	// BatchHash is the hash of the content of the batch.
	BatchHash hash.Hash `json:"batch_hash"`
}

// Sign signs the proposal header.
func (ph *ProposalHeader) Sign(signer signature.Signer, runtimeID common.Namespace) (*signature.RawSignature, error) {
	sigCtx, err := ProposalSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return nil, fmt.Errorf("signature context error: %w", err)
	}

	signature, err := signature.Sign(signer, sigCtx, cbor.Marshal(ph))
	if err != nil {
		return nil, err
	}
	return &signature.Signature, nil
}

// Equal compares against another proposal header for equality.
func (ph *ProposalHeader) Equal(other *ProposalHeader) bool {
	if ph.Round != other.Round {
		return false
	}
	if !ph.PreviousHash.Equal(&other.PreviousHash) {
		return false
	}
	if !ph.BatchHash.Equal(&other.BatchHash) {
		return false
	}
	return true
}

// Proposal is a batch proposal.
type Proposal struct {
	// NodeID is the public key of the node that generated this proposal.
	NodeID signature.PublicKey `json:"node_id"`

	// Header is the proposal header.
	Header ProposalHeader `json:"header"`

	// Signature is the proposal header signature.
	Signature signature.RawSignature `json:"sig"`

	// Batch is an ordered list of all transaction hashes that should be in a batch. In case of
	// the proposal being submitted as equivocation evidence, this field should be omitted.
	Batch []hash.Hash `json:"batch,omitempty"`
}

// Sign signs the proposal header and sets the signature on the proposal.
func (p *Proposal) Sign(signer signature.Signer, runtimeID common.Namespace) error {
	if !p.NodeID.Equal(signer.Public()) {
		return fmt.Errorf("node ID does not match signer (ID: %s signer: %s)", p.NodeID, signer.Public())
	}

	sig, err := p.Header.Sign(signer, runtimeID)
	if err != nil {
		return err
	}
	p.Signature = *sig
	return nil
}

// Verify verifies that the header signature is valid.
func (p *Proposal) Verify(runtimeID common.Namespace) error {
	sigCtx, err := ProposalSignatureContext.WithSuffix(runtimeID.String())
	if err != nil {
		return fmt.Errorf("roothash/commitment: signature context error: %w", err)
	}

	if !p.NodeID.Verify(sigCtx, cbor.Marshal(p.Header), p.Signature[:]) {
		return fmt.Errorf("roothash/commitment: signature verification failed")
	}
	return nil
}

// GetTransactionScheduler returns the transaction scheduler of the provided
// committee based on the provided round.
func GetTransactionScheduler(committee *scheduler.Committee, round uint64) (*scheduler.CommitteeNode, error) {
	workers := committee.Workers()
	numNodes := uint64(len(workers))
	if numNodes == 0 {
		return nil, fmt.Errorf("GetTransactionScheduler: no workers in commmittee")
	}
	schedulerIdx := round % numNodes
	return workers[schedulerIdx], nil
}
