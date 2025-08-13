// Package api implements the root hash backend API and common datastructures.
package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// ModuleName is a unique module name for the roothash module.
	ModuleName = "roothash"

	// RoundLatest is a special round number always referring to the latest round.
	RoundLatest uint64 = math.MaxUint64
	// RoundInvalid is a special round number that refers to an invalid round.
	RoundInvalid uint64 = math.MaxUint64 - 1
	// TimeoutNever is the timeout value that never expires.
	TimeoutNever int64 = 0

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

	// ErrNoCommittee is the error returned when there is no committee.
	ErrNoCommittee = errors.New(ModuleName, 6, "roothash: no committee")

	// ErrMaxMessagesTooBig is the error returned when the MaxMessages parameter is set to a value
	// larger than the MaxRuntimeMessages specified in consensus parameters.
	ErrMaxMessagesTooBig = errors.New(ModuleName, 7, "roothash: max runtime messages is too big")

	// ErrRuntimeDoesNotSlash is the error returned when misbehaviour evidence is submitted for a
	// runtime that does not slash.
	ErrRuntimeDoesNotSlash = errors.New(ModuleName, 8, "roothash: runtime does not slash")

	// ErrDuplicateEvidence is the error returned when submitting already existing evidence.
	ErrDuplicateEvidence = errors.New(ModuleName, 9, "roothash: duplicate evidence")

	// ErrInvalidEvidence is the error returned when an invalid evidence is submitted.
	ErrInvalidEvidence = errors.New(ModuleName, 10, "roothash: invalid evidence")

	// ErrIncomingMessageQueueFull is the error returned when the incoming message queue is full.
	ErrIncomingMessageQueueFull = errors.New(ModuleName, 11, "roothash: incoming message queue full")

	// ErrIncomingMessageInsufficientFee is the error returned when the provided fee is smaller than
	// the configured minimum incoming message submission fee.
	ErrIncomingMessageInsufficientFee = errors.New(ModuleName, 12, "roothash: insufficient fee")

	// ErrMaxInMessagesTooBig is the error returned when the MaxInMessages parameter is set to a
	// value larger than the MaxInRuntimeMessages specified in consensus parameters.
	ErrMaxInMessagesTooBig = errors.New(ModuleName, 13, "roothash: max incoming runtime messages is too big")

	// MethodExecutorCommit is the method name for executor commit submission.
	MethodExecutorCommit = transaction.NewMethodName(ModuleName, "ExecutorCommit", ExecutorCommit{})

	// MethodEvidence is the method name for submitting evidence of node misbehavior.
	MethodEvidence = transaction.NewMethodName(ModuleName, "Evidence", Evidence{})

	// MethodSubmitMsg is the method name for queuing incoming runtime messages.
	MethodSubmitMsg = transaction.NewMethodName(ModuleName, "SubmitMsg", SubmitMsg{})

	// Methods is a list of all methods supported by the roothash backend.
	Methods = []transaction.MethodName{
		MethodExecutorCommit,
		MethodEvidence,
		MethodSubmitMsg,
	}
)

// Backend is a root hash implementation.
type Backend interface {
	// GetGenesisBlock returns the genesis block.
	GetGenesisBlock(ctx context.Context, request *RuntimeRequest) (*block.Block, error)

	// GetLatestBlock returns the latest block.
	//
	// The metadata contained in this block can be further used to get
	// the latest state from the storage backend.
	GetLatestBlock(ctx context.Context, request *RuntimeRequest) (*block.Block, error)

	// GetRuntimeState returns the given runtime's state.
	GetRuntimeState(ctx context.Context, request *RuntimeRequest) (*RuntimeState, error)

	// GetRoundRoots returns the stored state and I/O roots for the given runtime and round.
	GetRoundRoots(ctx context.Context, request *RoundRootsRequest) (*RoundRoots, error)

	// GetPastRoundRoots returns the stored past state and I/O roots for the given runtime.
	GetPastRoundRoots(ctx context.Context, request *RuntimeRequest) (map[uint64]RoundRoots, error)

	// GetLastRoundResults returns the given runtime's last normal round results.
	GetLastRoundResults(ctx context.Context, request *RuntimeRequest) (*RoundResults, error)

	// GetIncomingMessageQueueMeta returns the given runtime's incoming message queue metadata.
	GetIncomingMessageQueueMeta(ctx context.Context, request *RuntimeRequest) (*message.IncomingMessageQueueMeta, error)

	// GetIncomingMessageQueue returns the given runtime's queued incoming messages.
	GetIncomingMessageQueue(ctx context.Context, request *InMessageQueueRequest) ([]*message.IncomingMessage, error)

	// WatchBlocks returns a channel that produces a stream of
	// annotated blocks.
	//
	// The latest block if any will get pushed to the stream immediately.
	// Subsequent blocks will be pushed into the stream as they are
	// confirmed.
	WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *AnnotatedBlock, pubsub.ClosableSubscription, error)

	// WatchEvents returns a stream of protocol events.
	WatchEvents(ctx context.Context, runtimeID common.Namespace) (<-chan *Event, pubsub.ClosableSubscription, error)

	// WatchExecutorCommitments returns a channel that produces a stream of executor commitments
	// observed in the consensus layer P2P network.
	//
	// Note that these commitments may not have been processed by consensus, commitments may be
	// received in any order and duplicates are possible.
	WatchExecutorCommitments(ctx context.Context, runtimeID common.Namespace) (<-chan *commitment.ExecutorCommitment, pubsub.ClosableSubscription, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// ConsensusParameters returns the roothash consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)

	// GetEvents returns the events at specified block height.
	GetEvents(ctx context.Context, height int64) ([]*Event, error)
}

// RuntimeRequest is a generic roothash get request for a specific runtime.
type RuntimeRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Height    int64            `json:"height"`
}

// RoundRootsRequest is a request for a specific runtime and round's state and I/O roots.
type RoundRootsRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Height    int64            `json:"height"`
	Round     uint64           `json:"round"`
}

// InMessageQueueRequest is a request for queued incoming messages.
type InMessageQueueRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Height    int64            `json:"height"`

	Offset uint64 `json:"offset,omitempty"`
	Limit  uint32 `json:"limit,omitempty"`
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

// SubmitMsg is the argument set for the SubmitMsg method.
type SubmitMsg struct {
	// ID is the destination runtime ID.
	ID common.Namespace `json:"id"`
	// Tag is an optional tag provided by the caller which is ignored and can be used to match
	// processed incoming message events later.
	Tag uint64 `json:"tag,omitempty"`
	// Fee is the fee sent into the runtime as part of the message being sent. The fee is
	// transferred before the message is processed by the runtime.
	Fee quantity.Quantity `json:"fee,omitempty"`
	// Tokens are any tokens sent into the runtime as part of the message being sent. The tokens are
	// transferred before the message is processed by the runtime.
	Tokens quantity.Quantity `json:"tokens,omitempty"`
	// Data is arbitrary runtime-dependent data.
	Data []byte `json:"data,omitempty"`
}

// NewSubmitMsgTx creates a new incoming runtime message submission transaction.
func NewSubmitMsgTx(nonce uint64, fee *transaction.Fee, msg *SubmitMsg) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodSubmitMsg, msg)
}

// EvidenceKind is the evidence kind.
type EvidenceKind uint8

const (
	// EvidenceKindEquivocation is the evidence kind for equivocation.
	EvidenceKindEquivocation = 1
)

// Evidence is an evidence of node misbehaviour.
type Evidence struct {
	ID common.Namespace `json:"id"`

	EquivocationExecutor *EquivocationExecutorEvidence `json:"equivocation_executor,omitempty"`
	EquivocationProposal *EquivocationProposalEvidence `json:"equivocation_prop,omitempty"`
}

// Hash computes the evidence hash.
//
// Hash is derived by hashing the evidence kind and the public key of the signer.
// Assumes evidence has been validated.
func (ev *Evidence) Hash() (hash.Hash, error) {
	switch {
	case ev.EquivocationProposal != nil:
		return hash.NewFromBytes([]byte{EvidenceKindEquivocation}, ev.EquivocationProposal.ProposalA.NodeID[:]), nil
	case ev.EquivocationExecutor != nil:
		return hash.NewFromBytes([]byte{EvidenceKindEquivocation}, ev.EquivocationExecutor.CommitA.NodeID[:]), nil
	default:
		return hash.Hash{}, fmt.Errorf("cannot compute hash, invalid evidence")
	}
}

// ValidateBasic performs basic evidence validity checks.
func (ev *Evidence) ValidateBasic() error {
	switch {
	case ev.EquivocationExecutor != nil && ev.EquivocationProposal != nil:
		return fmt.Errorf("evidence has multiple fields set")
	case ev.EquivocationExecutor != nil:
		return ev.EquivocationExecutor.ValidateBasic(ev.ID)
	case ev.EquivocationProposal != nil:
		return ev.EquivocationProposal.ValidateBasic(ev.ID)
	default:
		return fmt.Errorf("evidence content has no fields set")
	}
}

// EquivocationExecutorEvidence is evidence of executor commitment equivocation.
type EquivocationExecutorEvidence struct {
	CommitA commitment.ExecutorCommitment `json:"commit_a"`
	CommitB commitment.ExecutorCommitment `json:"commit_b"`
}

// ValidateBasic performs stateless executor evidence validation checks.
//
// Particularly evidence is not verified to not be expired as this requires stateful checks.
func (ev *EquivocationExecutorEvidence) ValidateBasic(id common.Namespace) error {
	if ev.CommitA.Header.MostlyEqual(&ev.CommitB.Header) {
		return fmt.Errorf("commits are equal, no sign of equivocation")
	}

	if !ev.CommitA.NodeID.Equal(ev.CommitB.NodeID) {
		return fmt.Errorf("equivocation executor evidence signature public keys don't match")
	}

	if ev.CommitA.Header.SchedulerID != ev.CommitB.Header.SchedulerID {
		return fmt.Errorf("equivocation evidence scheduler IDs don't match")
	}

	if ev.CommitA.Header.Header.Round != ev.CommitB.Header.Header.Round {
		return fmt.Errorf("equivocation evidence commit headers not for same round")
	}

	if len(ev.CommitA.Messages) > 0 || len(ev.CommitB.Messages) > 0 {
		return fmt.Errorf("messages should be empty for equivocation evidence")
	}

	if err := ev.CommitA.ValidateBasic(); err != nil {
		return fmt.Errorf("equivocation evidence commit A not valid: %w", err)
	}
	if err := ev.CommitB.ValidateBasic(); err != nil {
		return fmt.Errorf("equivocation evidence commit B not valid: %w", err)
	}

	a := ev.CommitA.Header
	b := ev.CommitB.Header

	switch {
	// Note: ValidateBasic checks above ensure that none of these fields are nil.
	case a.Failure == commitment.FailureNone && b.Failure == commitment.FailureNone:
		if a.Header.PreviousHash.Equal(&b.Header.PreviousHash) &&
			a.Header.IORoot.Equal(b.Header.IORoot) &&
			a.Header.StateRoot.Equal(b.Header.StateRoot) &&
			a.Header.MessagesHash.Equal(b.Header.MessagesHash) {
			return fmt.Errorf("equivocation evidence commit headers match, no sign of equivocation")
		}
	default:
		if a.Failure == b.Failure {
			return fmt.Errorf("equivocation evidence failure indication fields match, no sign of equivocation")
		}
	}

	// Verify signatures.
	if err := ev.CommitA.Verify(id); err != nil {
		return fmt.Errorf("invalid signature for commit A: %w", err)
	}
	if err := ev.CommitB.Verify(id); err != nil {
		return fmt.Errorf("invalid signature for commit B: %w", err)
	}

	return nil
}

// EquivocationProposalEvidence is evidence of executor proposed batch equivocation.
type EquivocationProposalEvidence struct {
	ProposalA commitment.Proposal `json:"prop_a"`
	ProposalB commitment.Proposal `json:"prop_b"`
}

// ValidateBasic performs stateless batch evidence validation checks.
//
// Particularly evidence is not verified to not be expired as this requires stateful checks.
func (ev *EquivocationProposalEvidence) ValidateBasic(id common.Namespace) error {
	if ev.ProposalA.Header.Equal(&ev.ProposalB.Header) {
		return fmt.Errorf("proposal headers are equal, no sign of equivocation")
	}

	if !ev.ProposalA.NodeID.Equal(ev.ProposalB.NodeID) {
		return fmt.Errorf("equivocation proposal evidence signature public keys don't match")
	}

	if ev.ProposalA.Header.Round != ev.ProposalB.Header.Round {
		return fmt.Errorf("equivocation evidence proposal header rounds don't match")
	}

	if len(ev.ProposalA.Batch) > 0 || len(ev.ProposalB.Batch) > 0 {
		return fmt.Errorf("batch should be empty for equivocation evidence")
	}

	// Since we did the Equal check above, either BatchHash or PreviousHash must be different.

	// Verify signatures.
	if err := ev.ProposalA.Verify(id); err != nil {
		return fmt.Errorf("invalid signature for proposal A: %w", err)
	}
	if err := ev.ProposalB.Verify(id); err != nil {
		return fmt.Errorf("invalid signature for proposal B: %w", err)
	}

	return nil
}

// NewEvidenceTx creates a new evidence transaction.
func NewEvidenceTx(nonce uint64, fee *transaction.Fee, evidence *Evidence) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodEvidence, evidence)
}

// RuntimeState is the per-runtime state.
type RuntimeState struct {
	// Runtime is the latest per-epoch runtime descriptor.
	Runtime *registry.Runtime `json:"runtime"`
	// Suspended is a flag indicating whether the runtime is currently suspended.
	Suspended bool `json:"suspended,omitempty"`

	// GenesisBlock is the runtime's first block.
	GenesisBlock *block.Block `json:"genesis_block"`

	// LastBlock is the runtime's most recently generated block.
	LastBlock *block.Block `json:"last_block"`
	// LastBlockHeight is the height at which the runtime's most recent block was generated.
	LastBlockHeight int64 `json:"last_block_height"`

	// LastNormalRound is the runtime round which was normally processed by the runtime. This is
	// also the round that contains the message results for the last processed runtime messages.
	LastNormalRound uint64 `json:"last_normal_round"`
	// LastNormalHeight is the consensus block height corresponding to LastNormalRound.
	LastNormalHeight int64 `json:"last_normal_height"`

	// Committee is the committee the executor pool is collecting commitments for.
	Committee *scheduler.Committee `json:"committee,omitempty"`
	// CommitmentPool collects the executor commitments.
	CommitmentPool *commitment.Pool `json:"commitment_pool,omitempty"`
	// NextTimeout is the time at which the round is scheduled for forced finalization.
	NextTimeout int64 `json:"timeout,omitempty"`

	// LivenessStatistics contains the liveness statistics for the current epoch.
	LivenessStatistics *LivenessStatistics `json:"liveness_stats,omitempty"`
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

// EventKind returns a string representation of this event's kind.
func (e *ExecutorCommittedEvent) EventKind() string {
	return "executor_commit"
}

// ExecutionDiscrepancyDetectedEvent is an execute discrepancy detected event.
type ExecutionDiscrepancyDetectedEvent struct {
	// Round is the round in which the discrepancy was detected.
	Round uint64 `json:"round"`
	// Rank is the rank of the transaction scheduler.
	Rank uint64 `json:"rank"`
	// Timeout signals whether the discrepancy was due to a timeout.
	Timeout bool `json:"timeout"`
}

// EventKind returns a string representation of this event's kind.
func (e *ExecutionDiscrepancyDetectedEvent) EventKind() string {
	return "execution_discrepancy"
}

var _ events.CustomTypedAttribute = (*RuntimeIDAttribute)(nil)

// RuntimeIDAttribute is the event attribute for specifying runtime ID.
// ID is base64 encoded runtime ID.
type RuntimeIDAttribute struct {
	ID common.Namespace
}

// EventKind returns a string representation of this event's kind.
func (e *RuntimeIDAttribute) EventKind() string {
	return "runtime_id"
}

// EventValue returns a string representation of this event's kind.
func (e *RuntimeIDAttribute) EventValue() string {
	return base64.StdEncoding.EncodeToString(e.ID[:])
}

// DecodeValue decodes the attribute event value.
func (e *RuntimeIDAttribute) DecodeValue(value string) error {
	rtId := common.Namespace{} // nolint: revive
	if err := rtId.UnmarshalBase64([]byte(value)); err != nil {
		return err
	}
	copy(e.ID[:], rtId[:])
	return nil
}

// FinalizedEvent is a finalized event.
type FinalizedEvent struct {
	// Round is the round that was finalized.
	Round uint64 `json:"round"`
}

// EventKind returns a string representation of this event's kind.
func (e *FinalizedEvent) EventKind() string {
	return "finalized"
}

// InMsgProcessedEvent is an event of a specific incoming message being processed.
//
// In order to see details one needs to query the runtime at the specified round.
type InMsgProcessedEvent struct {
	// ID is the unique incoming message identifier.
	ID uint64 `json:"id"`
	// Round is the round where the incoming message was processed.
	Round uint64 `json:"round"`
	// Caller is the incoming message submitter address.
	Caller staking.Address `json:"caller"`
	// Tag is an optional tag provided by the caller.
	Tag uint64 `json:"tag,omitempty"`
}

// EventKind returns a string representation of this event's kind.
func (e *InMsgProcessedEvent) EventKind() string {
	return "in_msg_processed"
}

// MessageEvent is a runtime message processed event.
type MessageEvent struct {
	Module string `json:"module,omitempty"`
	Code   uint32 `json:"code,omitempty"`
	Index  uint32 `json:"index,omitempty"`

	// Result contains CBOR-encoded message execution result for successfully executed messages.
	Result cbor.RawMessage `json:"result,omitempty"`
}

// IsSuccess returns true if the event indicates that the message was successfully processed.
func (me *MessageEvent) IsSuccess() bool {
	return me.Code == errors.CodeNoError
}

// Event is a roothash event.
type Event struct {
	Height int64 `json:"height,omitempty"`

	RuntimeID common.Namespace `json:"runtime_id"`

	ExecutorCommitted            *ExecutorCommittedEvent            `json:"executor_committed,omitempty"`
	ExecutionDiscrepancyDetected *ExecutionDiscrepancyDetectedEvent `json:"execution_discrepancy,omitempty"`
	Finalized                    *FinalizedEvent                    `json:"finalized,omitempty"`
	InMsgProcessed               *InMsgProcessedEvent               `json:"in_msg_processed,omitempty"`
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

// GenesisRuntimeState contains state for runtimes that are restored in a genesis block.
type GenesisRuntimeState struct {
	registry.RuntimeGenesis

	// MessageResults are the message results emitted at the last processed round.
	MessageResults []*MessageEvent `json:"message_results,omitempty"`
}

// Genesis is the roothash genesis state.
type Genesis struct {
	// Parameters are the roothash consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// RuntimeStates are the runtime states at genesis.
	RuntimeStates map[common.Namespace]*GenesisRuntimeState `json:"runtime_states,omitempty"`
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

	// MaxRuntimeMessages is the maximum number of allowed messages that can be emitted by a runtime
	// in a single round.
	MaxRuntimeMessages uint32 `json:"max_runtime_messages"`

	// MaxInRuntimeMessages is the maximum number of allowed incoming messages that can be queued.
	MaxInRuntimeMessages uint32 `json:"max_in_runtime_messages"`

	// MaxEvidenceAge is the maximum age of submitted evidence in the number of rounds.
	MaxEvidenceAge uint64 `json:"max_evidence_age"`

	// MaxPastRootsStored is the maximum number of past runtime state and I/O
	// roots that are stored in the consensus state.
	MaxPastRootsStored uint64 `json:"max_past_roots_stored,omitempty"`
}

// ConsensusParameterChanges are allowed roothash consensus parameter changes.
type ConsensusParameterChanges struct {
	// GasCosts are the new gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MaxRuntimeMessages is the new maximum number of emitted runtime messages.
	MaxRuntimeMessages *uint32 `json:"max_runtime_messages"`

	// MaxInRuntimeMessages is the new maximum number of incoming queued runtime messages.
	MaxInRuntimeMessages *uint32 `json:"max_in_runtime_messages"`

	// MaxEvidenceAge is the new maximum evidence age.
	MaxEvidenceAge *uint64 `json:"max_evidence_age"`

	// MaxPastRootsStored is the new maximum number of past runtime state and I/O
	// roots that are stored in the consensus state.
	MaxPastRootsStored *uint64 `json:"max_past_roots_stored,omitempty"`
}

// Apply applies changes to the given consensus parameters.
func (c *ConsensusParameterChanges) Apply(params *ConsensusParameters) error {
	if c.GasCosts != nil {
		params.GasCosts = c.GasCosts
	}
	if c.MaxRuntimeMessages != nil {
		params.MaxRuntimeMessages = *c.MaxRuntimeMessages
	}
	if c.MaxInRuntimeMessages != nil {
		params.MaxInRuntimeMessages = *c.MaxInRuntimeMessages
	}
	if c.MaxEvidenceAge != nil {
		params.MaxEvidenceAge = *c.MaxEvidenceAge
	}
	if c.MaxPastRootsStored != nil {
		params.MaxPastRootsStored = *c.MaxPastRootsStored
	}
	return nil
}

const (
	// GasOpComputeCommit is the gas operation identifier for compute commits.
	GasOpComputeCommit transaction.Op = "compute_commit"

	// GasOpProposerTimeout is the gas operation identifier for executor propose timeout cost.
	GasOpProposerTimeout transaction.Op = "proposer_timeout"

	// GasOpEvidence is the gas operation identifier for evidence submission transaction cost.
	GasOpEvidence transaction.Op = "evidence"

	// GasOpSubmitMsg is the gas operation identifier for message submission transaction cost.
	GasOpSubmitMsg transaction.Op = "submit_msg"
)

// XXX: Define reasonable default gas costs.

// DefaultGasCosts are the "default" gas costs for operations.
var DefaultGasCosts = transaction.Costs{
	GasOpComputeCommit:   1000,
	GasOpProposerTimeout: 1000,
	GasOpEvidence:        1000,
	GasOpSubmitMsg:       1000,
}

// VerifyRuntimeParameters verifies whether the runtime parameters are valid in the context of the
// roothash service.
func VerifyRuntimeParameters(rt *registry.Runtime, params *ConsensusParameters) error {
	if rt.Executor.MaxMessages > params.MaxRuntimeMessages {
		return ErrMaxMessagesTooBig
	}
	if rt.TxnScheduler.MaxInMessages > params.MaxInRuntimeMessages {
		return ErrMaxInMessagesTooBig
	}
	return nil
}

// RoundRoots holds the per-round state and I/O roots that are stored in
// consensus state.
type RoundRoots struct {
	// Serialize this struct as an array with two elements to save space in
	// the consensus state.
	_ struct{} `cbor:",toarray"` //nolint

	StateRoot hash.Hash
	IORoot    hash.Hash
}
