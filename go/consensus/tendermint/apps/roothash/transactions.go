package roothash

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var _ commitment.SignatureVerifier = (*roothashSignatureVerifier)(nil)

type roothashSignatureVerifier struct {
	ctx       *abciAPI.Context
	runtimeID common.Namespace
	scheduler *schedulerState.MutableState
	registry  *registryState.MutableState
}

// VerifyCommitteeSignatures verifies that the given signatures come from
// the current committee members of the given kind.
//
// Implements commitment.SignatureVerifier.
func (sv *roothashSignatureVerifier) VerifyCommitteeSignatures(kind scheduler.CommitteeKind, sigs []signature.Signature) error {
	if len(sigs) == 0 {
		return nil
	}

	committee, err := sv.scheduler.Committee(sv.ctx, kind, sv.runtimeID)
	if err != nil {
		return err
	}
	if committee == nil {
		return roothash.ErrInvalidRuntime
	}

	// TODO: Consider caching this set?
	pks := make(map[signature.PublicKey]bool)
	for _, m := range committee.Members {
		pks[m.PublicKey] = true
	}

	for _, sig := range sigs {
		if !pks[sig.PublicKey] {
			return fmt.Errorf("roothash: signature is not from a valid committee member")
		}
	}
	return nil
}

// VerifyTxnSchedulerSignature verifies that the given signatures come from
// the transaction scheduler at provided round.
//
// Implements commitment.SignatureVerifier.
func (sv *roothashSignatureVerifier) VerifyTxnSchedulerSignature(sig signature.Signature, round uint64) error {
	committee, err := sv.scheduler.Committee(sv.ctx, scheduler.KindComputeExecutor, sv.runtimeID)
	if err != nil {
		return err
	}
	if committee == nil {
		return roothash.ErrInvalidRuntime
	}
	scheduler, err := commitment.GetTransactionScheduler(committee, round)
	if err != nil {
		return fmt.Errorf("roothash: error getting transaction scheduler: %w", err)
	}
	if !scheduler.PublicKey.Equal(sig.PublicKey) {
		return fmt.Errorf("roothash: signature is not from a valid transaction scheduler")
	}
	return nil
}

// getRuntimeState fetches the current runtime state and performs common
// processing and error handling.
func (app *rootHashApplication) getRuntimeState(
	ctx *abciAPI.Context,
	state *roothashState.MutableState,
	id common.Namespace,
) (*roothash.RuntimeState, commitment.SignatureVerifier, commitment.NodeLookup, error) {
	// Fetch current runtime state.
	rtState, err := state.RuntimeState(ctx, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("roothash: failed to fetch runtime state: %w", err)
	}
	if rtState.Suspended {
		return nil, nil, nil, roothash.ErrRuntimeSuspended
	}
	if rtState.ExecutorPool == nil {
		return nil, nil, nil, roothash.ErrNoExecutorPool
	}

	// Create signature verifier.
	sv := &roothashSignatureVerifier{
		ctx:       ctx,
		runtimeID: id,
		scheduler: schedulerState.NewMutableState(ctx.State()),
		registry:  registryState.NewMutableState(ctx.State()),
	}

	// Create node lookup.
	nl := registryState.NewMutableState(ctx.State())

	return rtState, sv, nl, nil
}

func (app *rootHashApplication) executorProposerTimeout(
	ctx *abciAPI.Context,
	state *roothashState.MutableState,
	rpt *roothash.ExecutorProposerTimeoutRequest,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, roothash.GasOpProposerTimeout, params.GasCosts); err != nil {
		return err
	}

	rtState, sv, nl, err := app.getRuntimeState(ctx, state, rpt.ID)
	if err != nil {
		return err
	}

	// Ensure enough blocks have passed since round start.
	proposerTimeout := rtState.Runtime.TxnScheduler.ProposerTimeout
	currentBlockHeight := rtState.CurrentBlockHeight
	if height := ctx.BlockHeight(); height < currentBlockHeight+proposerTimeout {
		ctx.Logger().Error("failed requesting proposer round timeout, timeout not allowed yet",
			"height", height,
			"current_block_height", currentBlockHeight,
			"proposer_timeout", proposerTimeout,
		)
		return roothash.ErrProposerTimeoutNotAllowed
	}

	// Ensure request is valid.
	if err = rtState.ExecutorPool.CheckProposerTimeout(ctx, rtState.CurrentBlock, sv, nl, ctx.TxSigner(), rpt.Round); err != nil {
		ctx.Logger().Error("failed requesting proposer round timeout",
			"err", err,
			"round", rtState.CurrentBlock.Header.Round,
			"request", rpt,
		)
		return err
	}

	// Timeout triggered by executor node, emit empty error block.
	ctx.Logger().Error("proposer round timeout",
		"round", rpt.Round,
		"err", err,
		logging.LogEvent, roothash.LogEventRoundFailed,
	)
	if err = app.emitEmptyBlock(ctx, rtState, block.RoundFailed); err != nil {
		return fmt.Errorf("failed to emit empty block: %w", err)
	}

	// Update runtime state.
	if err = state.SetRuntimeState(ctx, rtState); err != nil {
		return fmt.Errorf("failed to set runtime state: %w", err)
	}

	return nil
}

func (app *rootHashApplication) executorCommit(
	ctx *abciAPI.Context,
	state *roothashState.MutableState,
	cc *roothash.ExecutorCommit,
) (err error) {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("ComputeCommit: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, roothash.GasOpComputeCommit, params.GasCosts); err != nil {
		return err
	}

	rtState, sv, nl, err := app.getRuntimeState(ctx, state, cc.ID)
	if err != nil {
		return err
	}

	// Account for gas consumed by messages.
	msgGasAccountant := func(msgs []message.Message) error {
		// Deliver messages in the simulation context to estimate gas.
		msgCtx := ctx.WithSimulation()
		defer msgCtx.Close()

		return app.processRuntimeMessages(msgCtx, rtState, msgs)
	}

	for _, commit := range cc.Commits {
		if err = rtState.ExecutorPool.AddExecutorCommitment(
			ctx,
			rtState.CurrentBlock,
			sv,
			nl,
			&commit, // nolint: gosec
			msgGasAccountant,
		); err != nil {
			ctx.Logger().Error("failed to add compute commitment to round",
				"err", err,
				"round", rtState.CurrentBlock.Header.Round,
			)
			return err
		}
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	// Try to finalize round.
	if err = app.tryFinalizeBlock(ctx, rtState, false); err != nil {
		ctx.Logger().Error("failed to finalize block",
			"err", err,
		)
		return err
	}

	// Update runtime state.
	if err = state.SetRuntimeState(ctx, rtState); err != nil {
		return fmt.Errorf("failed to set runtime state: %w", err)
	}

	// Emit events for all accepted commits.
	for _, commit := range cc.Commits {
		evV := ValueExecutorCommitted{
			ID: cc.ID,
			Event: roothash.ExecutorCommittedEvent{
				Commit: commit,
			},
		}
		ctx.EmitEvent(
			tmapi.NewEventBuilder(app.Name()).
				Attribute(KeyExecutorCommitted, cbor.Marshal(evV)).
				Attribute(KeyRuntimeID, ValueRuntimeID(cc.ID)),
		)
	}

	return nil
}

func (app *rootHashApplication) submitEvidence(
	ctx *abciAPI.Context,
	state *roothashState.MutableState,
	evidence *roothash.Evidence,
) error {
	// Validate proposal content basics.
	if err := evidence.ValidateBasic(); err != nil {
		ctx.Logger().Error("Evidence: submitted evidence not valid",
			"evidence", evidence,
			"err", err,
		)
		return fmt.Errorf("%w: %v", roothash.ErrInvalidEvidence, err)
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("Evidence: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, roothash.GasOpEvidence, params.GasCosts); err != nil {
		return err
	}

	rtState, _, _, err := app.getRuntimeState(ctx, state, evidence.ID)
	if err != nil {
		return err
	}

	if len(rtState.Runtime.Staking.Slashing) == 0 {
		// No slashing instructions for runtime, no point in collecting evidence.
		ctx.Logger().Error("Evidence: runtime has no slashing instructions",
			"err", roothash.ErrRuntimeDoesNotSlash,
		)
		return roothash.ErrRuntimeDoesNotSlash
	}
	slash := rtState.Runtime.Staking.Slashing[staking.SlashRuntimeEquivocation].Amount
	if slash.IsZero() {
		// Slash amount is zero for runtime, no point in collecting evidence.
		ctx.Logger().Error("Evidence: runtime has no slashing instructions for equivocation",
			"err", roothash.ErrRuntimeDoesNotSlash,
		)
		return roothash.ErrRuntimeDoesNotSlash
	}

	// Ensure evidence is not expired.
	var round uint64
	var pk signature.PublicKey
	switch {
	case evidence.EquivocationExecutor != nil:
		commitA, _ := evidence.EquivocationExecutor.CommitA.Open()

		if commitA.Body.Header.Round+params.MaxEvidenceAge < rtState.CurrentBlock.Header.Round {
			ctx.Logger().Error("Evidence: commitment equivocation evidence expired",
				"evidence", evidence.EquivocationExecutor,
				"current_round", rtState.CurrentBlock.Header.Round,
				"max_evidence_age", params.MaxEvidenceAge,
			)
			return fmt.Errorf("%w: equivocation evidence expired", roothash.ErrInvalidEvidence)
		}
		round = commitA.Body.Header.Round
		pk = commitA.Signature.PublicKey
	case evidence.EquivocationBatch != nil:
		var batchA commitment.ProposedBatch
		_ = evidence.EquivocationBatch.BatchA.Open(&batchA)

		if batchA.Header.Round+params.MaxEvidenceAge < rtState.CurrentBlock.Header.Round {
			ctx.Logger().Error("Evidence: proposed batch equivocation evidence expired",
				"evidence", evidence.EquivocationExecutor,
				"current_round", rtState.CurrentBlock.Header.Round,
				"max_evidence_age", params.MaxEvidenceAge,
			)
			return fmt.Errorf("%w: equivocation evidence expired", roothash.ErrInvalidEvidence)
		}
		round = batchA.Header.Round
		pk = evidence.EquivocationBatch.BatchA.Signature.PublicKey
	}

	// Evidence is valid. Store the evidence and slash the node.
	evHash, err := evidence.Hash()
	if err != nil {
		return fmt.Errorf("error computing evidence hash: %w", err)
	}
	b, err := state.ImmutableState.EvidenceHashExists(ctx, rtState.Runtime.ID, round, evHash)
	if err != nil {
		return fmt.Errorf("error querying evidence hash: %w", err)
	}
	if b {
		return roothash.ErrDuplicateEvidence
	}
	if err = state.SetEvidenceHash(ctx, rtState.Runtime.ID, round, evHash); err != nil {
		return err
	}

	if err = onEvidenceRuntimeEquivocation(
		ctx,
		pk,
		rtState.Runtime.ID,
		&slash,
	); err != nil {
		return fmt.Errorf("error slashing runtime node: %w", err)
	}

	return nil
}
