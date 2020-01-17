// Package api implements the root hash backend API and common datastructures.
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
)

const (
	// ModuleName is a unique module name for the roothash module.
	ModuleName = "roothash"

	// LogEventExecutionDiscrepancyDetected is a log event value that signals
	// an execution discrepancy has been detected.
	LogEventExecutionDiscrepancyDetected = "roothash/execution_discrepancy_detected"
	// LogEventMergeDiscrepancyDetected is a log event value that signals
	// a merge discrepancy has been detected.
	LogEventMergeDiscrepancyDetected = "roothash/merge_discrepancy_detected"
	// LogEventTimerFired is a log event value that signals a timer has fired.
	LogEventTimerFired = "roothash/timer_fired"
	// LogEventRoundFailed is a log event value that signals a round has failed.
	LogEventRoundFailed = "roothash/round_failed"
	// LogEventMessageUnsat is a log event value that signals a roothash message was not satisfactory.
	LogEventMessageUnsat = "roothash/message_unsat"
)

var (
	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New(ModuleName, 1, "roothash: invalid argument")

	// ErrNotFound is the error returned when a block is not found.
	ErrNotFound = errors.New(ModuleName, 2, "roothash: block not found")

	// ErrInvalidRuntime is the error returned when the passed runtime is invalid.
	ErrInvalidRuntime = errors.New(ModuleName, 3, "roothash: invalid runtime")

	// ErrNoRound is the error returned when no round is in progress.
	ErrNoRound = errors.New(ModuleName, 4, "roothash: no round is in progress")

	// ErrRuntimeSuspended is the error returned when the passed runtime is suspended.
	ErrRuntimeSuspended = errors.New(ModuleName, 5, "roothash: runtime is suspended")

	// MethodExecutorCommit is the method name for executor commit submission.
	MethodExecutorCommit = transaction.NewMethodName(ModuleName, "ExecutorCommit", ExecutorCommit{})
	// MethodMergeCommit is the method name for merge commit submission.
	MethodMergeCommit = transaction.NewMethodName(ModuleName, "MergeCommit", MergeCommit{})

	// Methods is a list of all methods supported by the roothash backend.
	Methods = []transaction.MethodName{
		MethodExecutorCommit,
		MethodMergeCommit,
	}
)

// Backend is a root hash implementation.
type Backend interface {
	// GetGenesisBlock returns the genesis block.
	GetGenesisBlock(ctx context.Context, runtimeID common.Namespace, height int64) (*block.Block, error)

	// GetLatestBlock returns the latest block.
	//
	// The metadata contained in this block can be further used to get
	// the latest state from the storage backend.
	GetLatestBlock(ctx context.Context, runtimeID common.Namespace, height int64) (*block.Block, error)

	// WatchBlocks returns a channel that produces a stream of
	// annotated blocks.
	//
	// The latest block if any will get pushed to the stream immediately.
	// Subsequent blocks will be pushed into the stream as they are
	// confirmed.
	WatchBlocks(runtimeID common.Namespace) (<-chan *AnnotatedBlock, *pubsub.Subscription, error)

	// WatchEvents returns a stream of protocol events.
	WatchEvents(runtimeID common.Namespace) (<-chan *Event, *pubsub.Subscription, error)

	// TrackRuntime adds a runtime the history of which should be tracked.
	TrackRuntime(ctx context.Context, history BlockHistory) error

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// Cleanup cleans up the roothash backend.
	Cleanup()
}

// ExecutorCommit is the argument set for the ExecutorCommit method.
type ExecutorCommit struct {
	ID      common.Namespace                `json:"id"`
	Commits []commitment.ExecutorCommitment `json:"commits"`
}

// NewExecutorCommitTx creates a new executor commit transaction.
func NewExecutorCommitTx(nonce uint64, fee *transaction.Fee, runtimeID common.Namespace, commits []commitment.ExecutorCommitment) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodExecutorCommit, &ExecutorCommit{
		ID:      runtimeID,
		Commits: commits,
	})
}

// MergeCommit is the argument set for the MergeCommit method.
type MergeCommit struct {
	ID      common.Namespace             `json:"id"`
	Commits []commitment.MergeCommitment `json:"commits"`
}

// NewMergeCommitTx creates a new executor commit transaction.
func NewMergeCommitTx(nonce uint64, fee *transaction.Fee, runtimeID common.Namespace, commits []commitment.MergeCommitment) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodMergeCommit, &MergeCommit{
		ID:      runtimeID,
		Commits: commits,
	})
}

// AnnotatedBlock is an annotated roothash block.
type AnnotatedBlock struct {
	// Height is the underlying roothash backend's block height that
	// generated this block.
	Height int64 `json:"consensus_height"`

	// Block is the roothash block.
	Block *block.Block `json:"block"`
}

// ExecutionDiscrepancyDetectedEvent is an execute discrepancy detected event.
type ExecutionDiscrepancyDetectedEvent struct {
	// CommitteeID is the identifier of the executor committee where a
	// discrepancy has been detected.
	CommitteeID hash.Hash `json:"cid"`
	// Timeout signals whether the discrepancy was due to a timeout.
	Timeout bool `json:"timeout"`
}

// MergeDiscrepancyDetectedEvent is a merge discrepancy detected event.
type MergeDiscrepancyDetectedEvent struct {
}

// Event is a protocol event.
type Event struct {
	ExecutionDiscrepancyDetected *ExecutionDiscrepancyDetectedEvent
	MergeDiscrepancyDetected     *MergeDiscrepancyDetectedEvent
}

// MetricsMonitorable is the interface exposed by backends capable of
// providing metrics data.
type MetricsMonitorable interface {
	// WatchAllBlocks returns a channel that produces a stream of blocks.
	//
	// All blocks from all runtimes will be pushed into the stream
	// immediately as they are finalized.
	WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription)
}

// Genesis is the roothash genesis state.
type Genesis struct {
	// Parameters are the roothash consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// RuntimeStates is the per-runtime map of genesis blocks.
	RuntimeStates map[common.Namespace]*api.RuntimeGenesis `json:"runtime_states,omitempty"`
}

// ConsensusParameters are the roothash consensus parameters.
type ConsensusParameters struct {
	// GasCosts are the roothash transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// DebugDoNotSuspendRuntimes is true iff runtimes should not be suspended
	// for lack of paying maintenance fees.
	DebugDoNotSuspendRuntimes bool `json:"debug_do_not_suspend_runtimes,omitempty"`
}

const (
	// GasOpComputeCommit is the gas operation identifier for compute commits.
	GasOpComputeCommit transaction.Op = "compute_commit"
	// GasOpMergeCommit is the gas operation identifier for merge commits.
	GasOpMergeCommit transaction.Op = "merge_commit"
)

// SanityCheckBlocks examines the blocks table.
func SanityCheckBlocks(blocks map[common.Namespace]*block.Block) error {
	for _, blk := range blocks {
		hdr := blk.Header

		if hdr.Timestamp > uint64(time.Now().Unix()+61*60) {
			return fmt.Errorf("roothash: sanity check failed: block header timestamp is more than 1h1m in the future")
		}
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	unsafeFlags := g.Parameters.DebugDoNotSuspendRuntimes
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("roothash: sanity check failed: one or more unsafe debug flags set")
	}

	// Check blocks.
	for _, rtg := range g.RuntimeStates {
		if err := rtg.SanityCheck(true); err != nil {
			return err
		}
	}
	return nil
}
