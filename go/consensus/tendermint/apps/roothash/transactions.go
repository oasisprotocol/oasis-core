package roothash

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	roothashState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
)

var _ commitment.SignatureVerifier = (*roothashSignatureVerifier)(nil)

type roothashSignatureVerifier struct {
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

	committee, err := sv.scheduler.Committee(kind, sv.runtimeID)
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
			return errors.New("roothash: signature is not from a valid committee member")
		}
	}
	return nil
}

// getRuntimeState fetches the current runtime state and performs common
// processing and error handling.
func (app *rootHashApplication) getRuntimeState(
	ctx *abci.Context,
	state *roothashState.MutableState,
	id common.Namespace,
) (*roothashState.RuntimeState, commitment.SignatureVerifier, error) {
	// Fetch current runtime state.
	rtState, err := state.RuntimeState(id)
	if err != nil {
		return nil, nil, fmt.Errorf("roothash: failed to fetch runtime state: %w", err)
	}
	if rtState.Suspended {
		return nil, nil, roothash.ErrRuntimeSuspended
	}
	if rtState.Round == nil {
		return nil, nil, roothash.ErrNoRound
	}

	// Create signature verifier.
	sv := &roothashSignatureVerifier{
		runtimeID: id,
		scheduler: schedulerState.NewMutableState(ctx.State()),
	}

	// If the round was finalized, transition.
	if rtState.Round.CurrentBlock.Header.Round != rtState.CurrentBlock.Header.Round {
		app.logger.Debug("round was finalized, transitioning round",
			"round", rtState.CurrentBlock.Header.Round,
		)

		rtState.Round.Transition(rtState.CurrentBlock)
	}

	return rtState, sv, nil
}

func (app *rootHashApplication) computeCommit(
	ctx *abci.Context,
	state *roothashState.MutableState,
	cc *roothash.ComputeCommit,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		app.logger.Error("ComputeCommit: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, roothash.GasOpComputeCommit, params.GasCosts); err != nil {
		return err
	}

	rtState, sv, err := app.getRuntimeState(ctx, state, cc.ID)
	if err != nil {
		return err
	}
	defer state.SetRuntimeState(rtState)

	pools := make(map[*commitment.Pool]bool)
	for _, commit := range cc.Commits {
		var pool *commitment.Pool
		if pool, err = rtState.Round.AddComputeCommitment(&commit, sv); err != nil {
			app.logger.Error("failed to add compute commitment to round",
				"err", err,
				"round", rtState.CurrentBlock.Header.Round,
			)
			return err
		}

		pools[pool] = true
	}

	// Try to finalize compute rounds.
	for pool := range pools {
		app.tryFinalizeCompute(ctx, rtState, pool, false)
	}

	return nil
}

func (app *rootHashApplication) mergeCommit(
	ctx *abci.Context,
	state *roothashState.MutableState,
	mc *roothash.MergeCommit,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters()
	if err != nil {
		app.logger.Error("MergeCommit: failed to fetch consensus parameters",
			"err", err,
		)
		return err
	}
	if err = ctx.Gas().UseGas(1, roothash.GasOpMergeCommit, params.GasCosts); err != nil {
		return err
	}

	rtState, sv, err := app.getRuntimeState(ctx, state, mc.ID)
	if err != nil {
		return err
	}
	defer state.SetRuntimeState(rtState)

	// Add commitments.
	for _, commit := range mc.Commits {
		if err = rtState.Round.AddMergeCommitment(&commit, sv); err != nil {
			app.logger.Error("failed to add merge commitment to round",
				"err", err,
				"round", rtState.CurrentBlock.Header.Round,
			)
			return err
		}
	}

	// Try to finalize round.
	if err = app.tryFinalizeBlock(ctx, rtState, false); err != nil {
		app.logger.Error("failed to finalize block",
			"err", err,
		)
		return err
	}

	return nil
}
