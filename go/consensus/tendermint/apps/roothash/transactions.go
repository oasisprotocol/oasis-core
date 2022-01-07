package roothash

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// getRuntimeState fetches the current runtime state and performs common
// processing and error handling.
func (app *rootHashApplication) getRuntimeState(
	ctx *abciAPI.Context,
	state *roothashState.MutableState,
	id common.Namespace,
) (*roothash.RuntimeState, commitment.NodeLookup, error) {
	// Fetch current runtime state.
	rtState, err := state.RuntimeState(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("roothash: failed to fetch runtime state: %w", err)
	}
	if rtState.Suspended {
		return nil, nil, roothash.ErrRuntimeSuspended
	}
	if rtState.ExecutorPool == nil {
		return nil, nil, roothash.ErrNoExecutorPool
	}

	// Create node lookup.
	nl := registryState.NewMutableState(ctx.State())

	return rtState, nl, nil
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

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	rtState, nl, err := app.getRuntimeState(ctx, state, rpt.ID)
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
	if err = rtState.ExecutorPool.CheckProposerTimeout(ctx, rtState.CurrentBlock, nl, ctx.TxSigner(), rpt.Round); err != nil {
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

	rtState, nl, err := app.getRuntimeState(ctx, state, cc.ID)
	if err != nil {
		return err
	}

	// Account for gas consumed by messages.
	msgGasAccountant := func(msgs []message.Message) error {
		// Deliver messages in the simulation context to estimate gas.
		msgCtx := ctx.WithSimulation()
		defer msgCtx.Close()

		_, msgErr := app.processRuntimeMessages(msgCtx, rtState, msgs)
		return msgErr
	}

	for _, commit := range cc.Commits {
		if err = rtState.ExecutorPool.AddExecutorCommitment(
			ctx,
			rtState.CurrentBlock,
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

	// Emit events for all accepted commits.
	for _, commit := range cc.Commits {
		evV := ValueExecutorCommitted{
			ID: cc.ID,
			Event: roothash.ExecutorCommittedEvent{
				Commit: commit,
			},
		}
		ctx.EmitEvent(
			abciAPI.NewEventBuilder(app.Name()).
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

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	rtState, _, err := app.getRuntimeState(ctx, state, evidence.ID)
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
		commitA := evidence.EquivocationExecutor.CommitA

		if commitA.Header.Round+params.MaxEvidenceAge < rtState.CurrentBlock.Header.Round {
			ctx.Logger().Error("Evidence: commitment equivocation evidence expired",
				"evidence", evidence.EquivocationExecutor,
				"current_round", rtState.CurrentBlock.Header.Round,
				"max_evidence_age", params.MaxEvidenceAge,
			)
			return fmt.Errorf("%w: equivocation evidence expired", roothash.ErrInvalidEvidence)
		}
		round = commitA.Header.Round
		pk = commitA.NodeID
	case evidence.EquivocationProposal != nil:
		proposalA := evidence.EquivocationProposal.ProposalA

		if proposalA.Header.Round+params.MaxEvidenceAge < rtState.CurrentBlock.Header.Round {
			ctx.Logger().Error("Evidence: proposal equivocation evidence expired",
				"evidence", evidence.EquivocationExecutor,
				"current_round", rtState.CurrentBlock.Header.Round,
				"max_evidence_age", params.MaxEvidenceAge,
			)
			return fmt.Errorf("%w: equivocation evidence expired", roothash.ErrInvalidEvidence)
		}
		round = proposalA.Header.Round
		pk = proposalA.NodeID
	default:
		// This should never happen due to ValidateBasic check above.
		return roothash.ErrInvalidEvidence
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
		rtState.Runtime,
		&slash,
	); err != nil {
		return fmt.Errorf("error slashing runtime node: %w", err)
	}

	return nil
}

func (app *rootHashApplication) submitMsg(
	ctx *abciAPI.Context,
	state *roothashState.MutableState,
	msg *roothash.SubmitMsg,
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
	if err = ctx.Gas().UseGas(1, roothash.GasOpSubmitMsg, params.GasCosts); err != nil {
		return err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	rtState, _, err := app.getRuntimeState(ctx, state, msg.ID)
	if err != nil {
		return err
	}

	// If the maximum size of the queue is set to zero, bail early.
	if rtState.Runtime.TxnScheduler.MaxInMessages == 0 {
		return roothash.ErrIncomingMessageQueueFull
	}

	// If the submitted fee is smaller than the minimum fee, bail early.
	if msg.Fee.Cmp(&rtState.Runtime.Staking.MinInMessageFee) < 0 {
		return roothash.ErrIncomingMessageInsufficientFee
	}

	// Create a new transaction context and rollback in case we fail.
	ctx = ctx.NewTransaction()
	defer ctx.Close()

	// Transfer the given amount (fee + tokens) into the runtime account.
	totalAmount := msg.Fee.Clone()
	if err = totalAmount.Add(&msg.Tokens); err != nil {
		return err
	}

	st := stakingState.NewMutableState(ctx.State())
	rtAddress := staking.NewRuntimeAddress(rtState.Runtime.ID)
	if err = st.Transfer(ctx, ctx.CallerAddress(), rtAddress, totalAmount); err != nil {
		return err
	}

	// Fetch current incoming queue metadata.
	meta, err := state.IncomingMessageQueueMeta(ctx, rtState.Runtime.ID)
	if err != nil {
		return err
	}

	// Check if the queue is already full.
	if meta.Size >= rtState.Runtime.TxnScheduler.MaxInMessages {
		return roothash.ErrIncomingMessageQueueFull
	}

	// Queue message.
	inMsg := &message.IncomingMessage{
		ID:     meta.NextSequenceNumber,
		Caller: ctx.CallerAddress(),
		Tag:    msg.Tag,
		Fee:    msg.Fee,
		Tokens: msg.Tokens,
		Data:   msg.Data,
	}
	if err = state.SetIncomingMessageInQueue(ctx, rtState.Runtime.ID, inMsg); err != nil {
		return err
	}

	// Update next sequence number.
	meta.Size++
	meta.NextSequenceNumber++
	if err = state.SetIncomingMessageQueueMeta(ctx, rtState.Runtime.ID, meta); err != nil {
		return err
	}

	ctx.Commit()

	return nil
}
