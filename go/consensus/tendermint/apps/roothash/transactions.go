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
		return errors.New("roothash: no committee with which to verify signatures")
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

func (app *rootHashApplication) commit(
	ctx *abci.Context,
	state *roothashState.MutableState,
	id common.Namespace,
	msg interface{},
) error {
	logger := app.logger.With("is_check_only", ctx.IsCheckOnly())

	rtState, err := state.RuntimeState(id)
	if err != nil {
		return errors.Wrap(err, "roothash: failed to fetch runtime state")
	}
	if rtState == nil {
		return errNoSuchRuntime
	}
	runtime := rtState.Runtime

	if rtState.Round == nil {
		logger.Error("commit recevied when no round in progress")
		return errNoRound
	}

	latestBlock := rtState.CurrentBlock
	blockNr := latestBlock.Header.Round

	defer state.SetRuntimeState(rtState)

	// If the round was finalized, transition.
	if rtState.Round.CurrentBlock.Header.Round != latestBlock.Header.Round {
		logger.Debug("round was finalized, transitioning round",
			"round", blockNr,
		)

		rtState.Round.Transition(latestBlock)
	}

	// Create storage signature verifier.
	sv := &roothashSignatureVerifier{
		runtimeID: id,
		scheduler: schedulerState.NewMutableState(ctx.State()),
	}

	// Add the commitments.
	switch c := msg.(type) {
	case *roothash.MergeCommit:
		for _, commit := range c.Commits {
			if err = rtState.Round.AddMergeCommitment(&commit, sv); err != nil {
				logger.Error("failed to add merge commitment to round",
					"err", err,
					"round", blockNr,
				)
				return err
			}
		}

		// Try to finalize round.
		if !ctx.IsCheckOnly() {
			if err = app.tryFinalizeBlock(ctx, runtime, rtState, false); err != nil {
				logger.Error("failed to finalize block",
					"err", err,
				)
				return err
			}
		}
	case *roothash.ComputeCommit:
		pools := make(map[*commitment.Pool]bool)
		for _, commit := range c.Commits {
			var pool *commitment.Pool
			if pool, err = rtState.Round.AddComputeCommitment(&commit, sv); err != nil {
				logger.Error("failed to add compute commitment to round",
					"err", err,
					"round", blockNr,
				)
				return err
			}

			pools[pool] = true
		}

		// Try to finalize compute rounds.
		if !ctx.IsCheckOnly() {
			for pool := range pools {
				app.tryFinalizeCompute(ctx, runtime, rtState, pool, false)
			}
		}
	default:
		panic(fmt.Errorf("roothash: invalid type passed to commit(): %T", c))
	}

	return nil
}
