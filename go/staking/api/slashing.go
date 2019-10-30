package api

import (
	"math/big"

	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

// SlashReason is the reason why a node was slashed.
type SlashReason int

const (
	// SlashDoubleSigning is slashing due to double signing.
	SlashDoubleSigning SlashReason = 0

	SlashMax = SlashDoubleSigning
)

// String returns a string representation of a SlashReason.
func (s SlashReason) String() string {
	switch s {
	case SlashDoubleSigning:
		return "double-signing"
	default:
		return "[unknown slash reason]"
	}
}

// Slash is the per-reason slashing configuration.
type Slash struct {
	Share          Quantity            `json:"share"`
	FreezeInterval epochtime.EpochTime `json:"freeze_interval"`
}

// SlashAmountDenominator is the denominator for the slash share.
var SlashAmountDenominator *Quantity

// EvidenceKind is kind of evindence of a node misbehaving.
type EvidenceKind int

const (
	// EvidenceKindConsensus is consensus-layer specific evidence.
	EvidenceKindConsensus EvidenceKind = 0

	EvidenceKindMax = EvidenceKindConsensus
)

// String returns a string representation of an EvidenceKind.
func (k EvidenceKind) String() string {
	switch k {
	case EvidenceKindConsensus:
		return "consensus"
	default:
		return "[unknown evidence kind]"
	}
}

// Evidence is evidence of a node misbehaving.
type Evidence interface {
	// Kind returns the evidence kind.
	Kind() EvidenceKind
	// Unwrap returns the unwrapped evidence (if any).
	Unwrap() interface{}
}

// ConsensusEvidence is consensus backend-specific evidence.
type ConsensusEvidence struct {
	inner interface{}
}

var _ Evidence = (*ConsensusEvidence)(nil)

// Kind returns the evidence kind.
func (ce ConsensusEvidence) Kind() EvidenceKind {
	return EvidenceKindConsensus
}

// Unwrap returns the unwrapped evidence (if any).
func (ce ConsensusEvidence) Unwrap() interface{} {
	return ce.inner
}

// NewConsensusEvidence creates new consensus backend-specific evidence.
func NewConsensusEvidence(inner interface{}) ConsensusEvidence {
	return ConsensusEvidence{inner: inner}
}

func init() {
	// Denominated in 1000th of a percent.
	SlashAmountDenominator = NewQuantity()
	err := SlashAmountDenominator.FromBigInt(big.NewInt(100_000))
	if err != nil {
		panic(err)
	}
}
