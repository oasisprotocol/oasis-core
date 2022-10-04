package roothash

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *rootHashApplication) processRuntimeMessages(
	ctx *tmapi.Context,
	rtState *roothash.RuntimeState,
	msgs []message.Message,
) ([]*roothash.MessageEvent, error) {
	ctx = ctx.WithMessageExecution()
	defer ctx.Close()
	ctx = ctx.WithCallerAddress(staking.NewRuntimeAddress(rtState.Runtime.ID))
	defer ctx.Close()

	switch ctx.IsSimulation() {
	case false:
		// Delivery -- gas was already accounted for.
		ctx.SetGasAccountant(tmapi.NewNopGasAccountant())
	case true:
		// Gas estimation -- use parent gas accountant, discard state updates (there shouldn't be
		// any as we are using simulation mode, but make sure).
		ctx = ctx.NewTransaction()
		defer ctx.Close()
	}

	var events []*roothash.MessageEvent
	for i, msg := range msgs {
		ctx.Logger().Debug("dispatching runtime message",
			"index", i,
			"body", msg,
		)

		var result interface{}
		var err error
		switch {
		case msg.Staking != nil:
			result, err = app.md.Publish(ctx, roothashApi.RuntimeMessageStaking, msg.Staking)
		case msg.Registry != nil:
			result, err = app.md.Publish(ctx, roothashApi.RuntimeMessageRegistry, msg.Registry)
		default:
			// Unsupported message.
			err = roothash.ErrInvalidArgument
		}
		if err != nil {
			ctx.Logger().Warn("failed to process runtime message",
				"err", err,
				"runtime_id", rtState.Runtime.ID,
				"msg_index", i,
			)
		}

		// Make sure somebody actually handled the message, otherwise treat as unsupported.
		if err == tmapi.ErrNoSubscribers {
			err = roothash.ErrInvalidArgument
		}

		module, code := errors.Code(err)
		events = append(events, &roothash.MessageEvent{
			Index:  uint32(i),
			Module: module,
			Code:   code,
			Result: cbor.Marshal(result),
		})
	}
	return events, nil
}

func (app *rootHashApplication) doBeforeSchedule(ctx *api.Context, msg interface{}) (interface{}, error) {
	epoch := msg.(beacon.EpochTime)

	ctx.Logger().Debug("processing liveness statistics before scheduling",
		"epoch", epoch,
	)

	state := roothashState.NewMutableState(ctx.State())
	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes(ctx)

	for _, rt := range runtimes {
		if !rt.IsCompute() {
			continue
		}

		rtState, err := state.RuntimeState(ctx, rt.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch runtime state: %w", err)
		}
		if err = processLivenessStatistics(ctx, epoch, rtState); err != nil {
			return nil, fmt.Errorf("failed to process liveness statistics for %s: %w", rt.ID, err)
		}
	}
	return nil, nil
}

func (app *rootHashApplication) changeParameters(ctx *api.Context, msg interface{}, apply bool) (interface{}, error) {
	// Unmarshal changes and check if they should be applied to this module.
	proposal, ok := msg.(*governance.ChangeParametersProposal)
	if !ok {
		return nil, fmt.Errorf("roothash: failed to type assert change parameters proposal")
	}

	if proposal.Module != roothash.ModuleName {
		return nil, nil
	}

	var changes roothash.ConsensusParameterChanges
	if err := cbor.Unmarshal(proposal.Changes, &changes); err != nil {
		return nil, fmt.Errorf("roothash: failed to unmarshal consensus parameter changes: %w", err)
	}

	// Validate changes against current parameters.
	state := roothashState.NewMutableState(ctx.State())
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("roothash: failed to load consensus parameters: %w", err)
	}
	if err = changes.SanityCheck(); err != nil {
		return nil, fmt.Errorf("roothash: failed to validate consensus parameter changes: %w", err)
	}
	if err = changes.Apply(params); err != nil {
		return nil, fmt.Errorf("roothash: failed to apply consensus parameter changes: %w", err)
	}
	if err = params.SanityCheck(); err != nil {
		return nil, fmt.Errorf("roothash: failed to validate consensus parameters: %w", err)
	}

	// Apply changes.
	if apply {
		if err = state.SetConsensusParameters(ctx, params); err != nil {
			return nil, fmt.Errorf("roothash: failed to update consensus parameters: %w", err)
		}
	}

	// Non-nil response signals that changes are valid and were successfully applied (if required).
	return struct{}{}, nil
}
