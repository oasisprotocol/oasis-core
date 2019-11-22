// Package consensus provides the implementation agnostic consensus
// backend.
package api

import (
	"context"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

// moduleName is the module name used for error definitions.
const moduleName = "consensus"

// ErrNoCommittedBlocks is the error returned when there are no committed
// blocks and as such no state can be queried.
var ErrNoCommittedBlocks = errors.New(moduleName, 1, "consensus: no committed blocks")

// ClientBackend is a limited consensus interface used by clients that
// connect to the local node.
type ClientBackend interface {
	// SubmitTx submits a signed consensus transaction.
	SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error

	// TODO: Add things like following consensus blocks.
}

// Backend is an interface that a consensus backend must provide.
type Backend interface {
	ClientBackend

	// Synced returns a channel that is closed once synchronization is
	// complete.
	Synced() <-chan struct{}

	// ConsensusKey returns the consensus signing key.
	ConsensusKey() signature.PublicKey

	// GetAddresses returns the consensus backend addresses.
	GetAddresses() ([]node.ConsensusAddress, error)

	// RegisterGenesisHook registers a function to be called when the
	// consensus backend is initialized from genesis (e.g., on fresh
	// start).
	//
	// Note that these hooks block consensus genesis from completing
	// while they are running.
	RegisterGenesisHook(func())

	// RegisterHaltHook registers a function to be called when the
	// consensus Halt epoch height is reached.
	RegisterHaltHook(func(ctx context.Context, blockHeight int64, epoch epochtime.EpochTime))

	// SubmitEvidence submits evidence of misbehavior.
	SubmitEvidence(ctx context.Context, evidence Evidence) error

	// TransactionAuthHandler returns the transaction authentication handler.
	TransactionAuthHandler() TransactionAuthHandler

	// SubmissionManager returns the transaction submission manager.
	SubmissionManager() SubmissionManager

	// EpochTime returns the epochtime backend.
	EpochTime() epochtime.Backend

	// Beacon returns the beacon backend.
	Beacon() beacon.Backend

	// KeyManager returns the keymanager backend.
	KeyManager() keymanager.Backend

	// Registry returns the registry backend.
	Registry() registry.Backend

	// RootHash returns the roothash backend.
	RootHash() roothash.Backend

	// Staking returns the staking backend.
	Staking() staking.Backend

	// Scheduler returns the scheduler backend.
	Scheduler() scheduler.Backend

	// ToGenesis returns the genesis state at the specified block height.
	ToGenesis(ctx context.Context, blockHeight int64) (*genesis.Document, error)
}

// TransactionAuthHandler is the interface for handling transaction authentication
// (checking nonces and fees).
type TransactionAuthHandler interface {
	// GetSignerNonce returns the nonce that should be used by the given
	// signer for transmitting the next transaction.
	GetSignerNonce(ctx context.Context, id signature.PublicKey, height int64) (uint64, error)
}

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
