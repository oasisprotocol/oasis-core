// Package api implements the root hash backend API and common datastructures.
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

const (
	// ModuleName is a unique module name for the roothash module.
	ModuleName = "roothash"

	// LogEventExecutionDiscrepancyDetected is a log event value that signals
	// an execution discrepancy has been detected.
	LogEventExecutionDiscrepancyDetected = "roothash/execution_discrepancy_detected"
	// LogEventTimerFired is a log event value that signals a timer has fired.
	LogEventTimerFired = "roothash/timer_fired"
	// LogEventRoundFailed is a log event value that signals a round has failed.
	LogEventRoundFailed = "roothash/round_failed"
	// LogEventMessageUnsat is a log event value that signals a roothash message was not satisfactory.
	LogEventMessageUnsat = "roothash/message_unsat"
	// LogEventHistoryReindexing is a log event value that signals a roothash runtime reindexing
	// was run.
	LogEventHistoryReindexing = "roothash/history_reindexing"
)

var (
	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New(ModuleName, 1, "roothash: invalid argument")

	// ErrNotFound is the error returned when a block is not found.
	ErrNotFound = errors.New(ModuleName, 2, "roothash: block not found")

	// ErrInvalidRuntime is the error returned when the passed runtime is invalid.
	ErrInvalidRuntime = errors.New(ModuleName, 3, "roothash: invalid runtime")

	// ErrNoExecutorPool is the error returned when there is no executor pool.
	ErrNoExecutorPool = errors.New(ModuleName, 4, "roothash: no executor pool")

	// ErrRuntimeSuspended is the error returned when the passed runtime is suspended.
	ErrRuntimeSuspended = errors.New(ModuleName, 5, "roothash: runtime is suspended")

	// ErrProposerTimeoutNotAllowed is the error returned when proposer timeout is not allowed.
	ErrProposerTimeoutNotAllowed = errors.New(ModuleName, 6, "roothash: proposer timeout not allowed")

	// MethodExecutorCommit is the method name for executor commit submission.
	MethodExecutorCommit = transaction.NewMethodName(ModuleName, "ExecutorCommit", ExecutorCommit{})

	// MethodExecutorProposerTimeout is the method name for executor.
	MethodExecutorProposerTimeout = transaction.NewMethodName(ModuleName, "ExecutorProposerTimeout", ExecutorProposerTimeoutRequest{})

	// Methods is a list of all methods supported by the roothash backend.
	Methods = []transaction.MethodName{
		MethodExecutorCommit,
		MethodExecutorProposerTimeout,
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

	// GetEvents returns the events at specified block height.
	GetEvents(ctx context.Context, height int64) ([]*Event, error)

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

// ExecutorProposerTimeoutRequest is an executor proposer timeout request.
type ExecutorProposerTimeoutRequest struct {
	ID    common.Namespace `json:"id"`
	Round uint64           `json:"round"`
}

// NewRequestProposerTimeoutTx creates a new request proposer timeout transaction.
func NewRequestProposerTimeoutTx(nonce uint64, fee *transaction.Fee, runtimeID common.Namespace, round uint64) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodExecutorProposerTimeout, &ExecutorProposerTimeoutRequest{
		ID:    runtimeID,
		Round: round,
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

// ExecutorCommittedEvent is an event emitted each time an executor node commits.
type ExecutorCommittedEvent struct {
	// Commit is the executor commitment.
	Commit commitment.ExecutorCommitment `json:"commit"`
}

// ExecutionDiscrepancyDetectedEvent is an execute discrepancy detected event.
type ExecutionDiscrepancyDetectedEvent struct {
	// Timeout signals whether the discrepancy was due to a timeout.
	Timeout bool `json:"timeout"`
}

// FinalizedEvent is a finalized event.
type FinalizedEvent struct {
	Round uint64 `json:"round"`
}

// Event is a roothash event.
type Event struct {
	Height int64     `json:"height,omitempty"`
	TxHash hash.Hash `json:"tx_hash,omitempty"`

	RuntimeID common.Namespace `json:"runtime_id"`

	ExecutorCommitted            *ExecutorCommittedEvent            `json:"executor_committed,omitempty"`
	ExecutionDiscrepancyDetected *ExecutionDiscrepancyDetectedEvent `json:"execution_discrepancy,omitempty"`
	FinalizedEvent               *FinalizedEvent                    `json:"finalized,omitempty"`
}

// MetricsMonitorable is the interface exposed by backends capable of
// providing metrics data.
type MetricsMonitorable interface {
	// WatchAllBlocks returns a channel that produces a stream of blocks.
	//
	// All blocks from all tracked runtimes will be pushed into the stream
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

	// DebugBypassStake is true iff the roothash should bypass all of the staking
	// related checks and operations.
	DebugBypassStake bool `json:"debug_bypass_stake,omitempty"`
}

const (
	// GasOpComputeCommit is the gas operation identifier for compute commits.
	GasOpComputeCommit transaction.Op = "compute_commit"

	// GasOpProposerTimeout is the gas operation identifier for executor propose timeout cost.
	GasOpProposerTimeout transaction.Op = "proposer_timeout"
)

// XXX: Define reasonable default gas costs.

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpComputeCommit:   1000,
	GasOpProposerTimeout: 1000,
}

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
	unsafeFlags := g.Parameters.DebugDoNotSuspendRuntimes || g.Parameters.DebugBypassStake
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
