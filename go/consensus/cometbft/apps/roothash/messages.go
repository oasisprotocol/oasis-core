package roothash

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/features"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/migrations"
)

func fetchRuntimeMessages(
	ctx *tmapi.Context,
	state *roothashState.MutableState,
	runtimeID common.Namespace,
	limit uint32,
) ([]*message.IncomingMessage, error) {
	if limit == 0 {
		return []*message.IncomingMessage{}, nil
	}

	msgs, err := state.IncomingMessageQueue(ctx, runtimeID, 0, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch incoming message queue: %w", err)
	}

	return msgs, nil
}

func verifyRuntimeMessages(
	ctx *tmapi.Context,
	msgs []*message.IncomingMessage,
	h *hash.Hash,
) error {
	if inMsgsHash := message.InMessagesHash(msgs); !inMsgsHash.Equal(h) {
		ctx.Logger().Debug("failed to verify incoming messages hash",
			"in_msgs_hash", inMsgsHash,
			"ec_in_msgs_hash", *h,
		)

		return fmt.Errorf("failed to verify incoming messages hash")
	}

	return nil
}

func (app *Application) removeRuntimeMessages(
	ctx *tmapi.Context,
	state *roothashState.MutableState,
	runtimeID common.Namespace,
	msgs []*message.IncomingMessage,
	round uint64,
) error {
	if len(msgs) == 0 {
		return nil
	}

	// Remove processed messages from the incoming message queue.
	meta, err := state.IncomingMessageQueueMeta(ctx, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to fetch incoming message queue metadata: %w", err)
	}

	for _, msg := range msgs {
		err = state.RemoveIncomingMessageFromQueue(ctx, runtimeID, msg.ID)
		if err != nil {
			return fmt.Errorf("failed to remove processed incoming message from queue: %w", err)
		}

		if meta.Size == 0 {
			// This should NEVER happen.
			return tmapi.UnavailableStateError(fmt.Errorf("inconsistent queue size (state corruption?)"))
		}
		meta.Size--

		ctx.EmitEvent(
			tmapi.NewEventBuilder(app.Name()).
				TypedAttribute(&roothash.InMsgProcessedEvent{
					ID:     msg.ID,
					Round:  round,
					Caller: msg.Caller,
					Tag:    msg.Tag,
				}).
				TypedAttribute(&roothash.RuntimeIDAttribute{ID: runtimeID}),
		)
	}

	// Update the incoming message queue meta.
	err = state.SetIncomingMessageQueueMeta(ctx, runtimeID, meta)
	if err != nil {
		return fmt.Errorf("failed to set incoming message queue metadata: %w", err)
	}

	return nil
}

func (app *Application) processRuntimeMessages(
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

		var result any
		var err error
		switch {
		case msg.Staking != nil:
			result, err = app.md.Publish(ctx, roothashApi.RuntimeMessageStaking, msg.Staking)
		case msg.Registry != nil:
			result, err = app.md.Publish(ctx, roothashApi.RuntimeMessageRegistry, msg.Registry)
		case msg.Governance != nil:
			result, err = app.md.Publish(ctx, roothashApi.RuntimeMessageGovernance, msg.Governance)
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

func (app *Application) doBeforeSchedule(ctx *tmapi.Context, msg any) (any, error) {
	epoch := msg.(beacon.EpochTime)

	ok, err := features.IsFeatureVersion(ctx, migrations.Version242)
	if err != nil {
		return nil, err
	}
	if ok {
		ctx.Logger().Debug("finalizing rounds before scheduling",
			"epoch", epoch,
		)

		if err := app.tryFinalizeRounds(ctx); err != nil {
			return nil, err
		}
		if err := app.processRoundTimeouts(ctx); err != nil {
			return nil, err
		}
	}

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

func (app *Application) changeParameters(ctx *tmapi.Context, msg any, apply bool) (any, error) {
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
	var needToDeletePastRoots bool
	if changes.MaxPastRootsStored != nil && *changes.MaxPastRootsStored < params.MaxPastRootsStored {
		// If we've reduced the number of past roots stored, we need to delete
		// the excess when applying the new parameters.
		needToDeletePastRoots = true
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
		if needToDeletePastRoots {
			err = state.ShrinkPastRoots(ctx, params.MaxPastRootsStored)
			if err != nil {
				return nil, fmt.Errorf("roothash: failed to shrink past stored roots: %w", err)
			}
		}

		if err = state.SetConsensusParameters(ctx, params); err != nil {
			return nil, fmt.Errorf("roothash: failed to update consensus parameters: %w", err)
		}
	}

	// Non-nil response signals that changes are valid and were successfully applied (if required).
	return struct{}{}, nil
}
