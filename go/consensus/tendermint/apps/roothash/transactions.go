package roothash

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

var _ commitment.SignatureVerifier = (*roothashSignatureVerifier)(nil)

type roothashSignatureVerifier struct {
	ctx       *abciAPI.Context
	runtimeID common.Namespace
	scheduler *schedulerState.MutableState
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

// getRuntimeState fetches the current runtime state and performs common
// processing and error handling.
func (app *rootHashApplication) getRuntimeState(
	ctx *abciAPI.Context,
	state *roothashState.MutableState,
	id common.Namespace,
) (*roothashState.RuntimeState, commitment.SignatureVerifier, commitment.NodeLookup, error) {
	// Fetch current runtime state.
	rtState, err := state.RuntimeState(ctx, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("roothash: failed to fetch runtime state: %w", err)
	}
	if rtState.Suspended {
		return nil, nil, nil, roothash.ErrRuntimeSuspended
	}
	if rtState.Round == nil {
		return nil, nil, nil, roothash.ErrNoRound
	}

	// Create signature verifier.
	sv := &roothashSignatureVerifier{
		ctx:       ctx,
		runtimeID: id,
		scheduler: schedulerState.NewMutableState(ctx.State()),
	}

	// Create node lookup.
	nl := registryState.NewMutableState(ctx.State())

	// If the round was finalized, transition.
	if rtState.Round.CurrentBlock.Header.Round != rtState.CurrentBlock.Header.Round {
		ctx.Logger().Debug("round was finalized, transitioning round",
			"round", rtState.CurrentBlock.Header.Round,
		)

		rtState.Round.Transition(rtState.CurrentBlock)
	}

	return rtState, sv, nl, nil
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

	for _, commit := range cc.Commits {
		if err = rtState.Round.AddExecutorCommitment(ctx, &commit, sv, nl); err != nil { // nolint: gosec
			ctx.Logger().Error("failed to add compute commitment to round",
				"err", err,
				"round", rtState.CurrentBlock.Header.Round,
			)
			return err
		}
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
