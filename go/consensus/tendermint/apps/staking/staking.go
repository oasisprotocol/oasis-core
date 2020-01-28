// Package staking implements the staking application.
package staking

import (
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

var _ abci.Application = (*stakingApplication)(nil)

type stakingApplication struct {
	state abci.ApplicationState
}

func (app *stakingApplication) Name() string {
	return AppName
}

func (app *stakingApplication) ID() uint8 {
	return AppID
}

func (app *stakingApplication) Methods() []transaction.MethodName {
	return staking.Methods
}

func (app *stakingApplication) Blessed() bool {
	return false
}

func (app *stakingApplication) Dependencies() []string {
	return nil
}

func (app *stakingApplication) OnRegister(state abci.ApplicationState) {
	app.state = state
}

func (app *stakingApplication) OnCleanup() {
}

func (app *stakingApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	regState := registryState.NewMutableState(ctx.State())

	// Look up the proposer's entity.
	var proposingEntity *signature.PublicKey
	proposerNode, err := regState.NodeByConsensusAddress(request.Header.ProposerAddress)
	if err != nil {
		ctx.Logger().Warn("failed to get proposer node",
			"err", err,
			"address", hex.EncodeToString(request.Header.ProposerAddress),
		)
	} else {
		proposingEntity = &proposerNode.EntityID
	}

	// Go through all signers of the previous block and resolve entities.
	signingEntities := app.resolveEntityIDsFromVotes(ctx, regState, request.GetLastCommitInfo())

	// Disburse fees from previous block.
	if err := app.disburseFees(ctx, proposingEntity, signingEntities); err != nil {
		return fmt.Errorf("staking: failed to disburse fees: %w", err)
	}

	// Track signing for rewards.
	if err := app.updateEpochSigning(ctx, signingEntities); err != nil {
		return fmt.Errorf("staking: failed to update epoch signing info: %w", err)
	}

	// Iterate over any submitted evidence of a validator misbehaving. Note that
	// the actual evidence has already been verified by Tendermint to be valid.
	for _, evidence := range request.ByzantineValidators {
		switch evidence.Type {
		case tmtypes.ABCIEvidenceTypeDuplicateVote:
			if err := onEvidenceDoubleSign(ctx, evidence.Validator.Address, evidence.Height, evidence.Time, evidence.Validator.Power); err != nil {
				return err
			}
		default:
			ctx.Logger().Warn("ignoring unknown evidence type",
				"evidence_type", evidence.Type,
			)
		}
	}

	return nil
}

func (app *stakingApplication) ExecuteTx(ctx *abci.Context, tx *transaction.Transaction) error {
	state := stakingState.NewMutableState(ctx.State())

	switch tx.Method {
	case staking.MethodTransfer:
		var xfer staking.Transfer
		if err := cbor.Unmarshal(tx.Body, &xfer); err != nil {
			return err
		}

		return app.transfer(ctx, state, &xfer)
	case staking.MethodBurn:
		var burn staking.Burn
		if err := cbor.Unmarshal(tx.Body, &burn); err != nil {
			return err
		}

		return app.burn(ctx, state, &burn)
	case staking.MethodAddEscrow:
		var escrow staking.Escrow
		if err := cbor.Unmarshal(tx.Body, &escrow); err != nil {
			return err
		}

		return app.addEscrow(ctx, state, &escrow)
	case staking.MethodReclaimEscrow:
		var reclaim staking.ReclaimEscrow
		if err := cbor.Unmarshal(tx.Body, &reclaim); err != nil {
			return err
		}

		return app.reclaimEscrow(ctx, state, &reclaim)
	case staking.MethodAmendCommissionSchedule:
		var amend staking.AmendCommissionSchedule
		if err := cbor.Unmarshal(tx.Body, &amend); err != nil {
			return err
		}

		return app.amendCommissionSchedule(ctx, state, &amend)
	default:
		return staking.ErrInvalidArgument
	}
}

func (app *stakingApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *stakingApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	// Persist any block fees so we can transfer them in the next block.
	stakingState.PersistBlockFees(ctx)

	if changed, epoch := app.state.EpochChanged(ctx); changed {
		return types.ResponseEndBlock{}, app.onEpochChange(ctx, epoch)
	}
	return types.ResponseEndBlock{}, nil
}

func (app *stakingApplication) onEpochChange(ctx *abci.Context, epoch epochtime.EpochTime) error {
	state := stakingState.NewMutableState(ctx.State())

	// Delegation unbonding after debonding period elapses.
	for _, e := range state.ExpiredDebondingQueue(epoch) {
		deb := e.Delegation
		shareAmount := deb.Shares.Clone()
		delegator := state.Account(e.DelegatorID)
		// NOTE: Could be the same account, so make sure to not have two duplicate
		//       copies of it and overwrite it later.
		var escrow *staking.Account
		if e.DelegatorID.Equal(e.EscrowID) {
			escrow = delegator
		} else {
			escrow = state.Account(e.EscrowID)
		}

		var tokens quantity.Quantity
		if err := escrow.Escrow.Debonding.Withdraw(&tokens, &deb.Shares, shareAmount); err != nil {
			ctx.Logger().Error("failed to redeem debonding shares",
				"err", err,
				"escrow_id", e.EscrowID,
				"delegator_id", e.DelegatorID,
				"shares", deb.Shares,
			)
			return errors.Wrap(err, "staking/tendermint: failed to redeem debonding shares")
		}
		tokenAmount := tokens.Clone()

		if err := quantity.Move(&delegator.General.Balance, &tokens, tokenAmount); err != nil {
			ctx.Logger().Error("failed to move debonded tokens",
				"err", err,
				"escrow_id", e.EscrowID,
				"delegator_id", e.DelegatorID,
				"shares", deb.Shares,
			)
			return errors.Wrap(err, "staking/tendermint: failed to redeem debonding shares")
		}

		// Update state.
		state.RemoveFromDebondingQueue(e.Epoch, e.DelegatorID, e.EscrowID, e.Seq)
		state.SetDebondingDelegation(e.DelegatorID, e.EscrowID, e.Seq, nil)
		state.SetAccount(e.DelegatorID, delegator)
		if !e.DelegatorID.Equal(e.EscrowID) {
			state.SetAccount(e.EscrowID, escrow)
		}

		ctx.Logger().Debug("released tokens",
			"escrow_id", e.EscrowID,
			"delegator_id", e.DelegatorID,
			"amount", tokenAmount,
		)

		evt := staking.ReclaimEscrowEvent{
			Owner:  e.DelegatorID,
			Escrow: e.EscrowID,
			Tokens: *tokenAmount,
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyReclaimEscrow, cbor.Marshal(evt)))
	}

	// Add signing rewards.
	if err := app.rewardEpochSigning(ctx, epoch); err != nil {
		ctx.Logger().Error("failed to add signing rewards",
			"err", err,
		)
		return errors.Wrap(err, "staking/tendermint: failed to add signing rewards")
	}

	return nil
}

func (app *stakingApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) error {
	return errors.New("tendermint/staking: unexpected timer")
}

// New constructs a new staking application instance.
func New() abci.Application {
	return &stakingApplication{}
}
