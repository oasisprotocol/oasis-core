package staking

import (
	"errors"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

// EventsFromCometBFT extracts staking events from CometBFT events.
func EventsFromCometBFT(
	tx cmttypes.Tx,
	height int64,
	tmEvents []cmtabcitypes.Event,
) ([]*api.Event, error) {
	var txHash hash.Hash
	switch tx {
	case nil:
		txHash.Empty()
	default:
		txHash = hash.NewFromBytes(tx)
	}

	var events []*api.Event
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the staking app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case eventsAPI.IsAttributeKind(key, &api.TakeEscrowEvent{}):
				// Take escrow event.
				var e api.TakeEscrowEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("staking: corrupt TakeEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Take: &e}}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.TransferEvent{}):
				// Transfer event.
				var e api.TransferEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("staking: corrupt Transfer event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Transfer: &e}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.ReclaimEscrowEvent{}):
				// Reclaim escrow event.
				var e api.ReclaimEscrowEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("staking: corrupt ReclaimEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Reclaim: &e}}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.AddEscrowEvent{}):
				// Add escrow event.
				var e api.AddEscrowEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("staking: corrupt AddEscrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{Add: &e}}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.DebondingStartEscrowEvent{}):
				// Debonding start escrow event.
				var e api.DebondingStartEscrowEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("staking: corrupt DebondingStart escrow event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Escrow: &api.EscrowEvent{DebondingStart: &e}}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.BurnEvent{}):
				// Burn event.
				var e api.BurnEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("staking: corrupt Burn event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, Burn: &e}
				events = append(events, evt)
			case eventsAPI.IsAttributeKind(key, &api.AllowanceChangeEvent{}):
				// Allowance change event.
				var e api.AllowanceChangeEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("staking: corrupt AllowanceChange event: %w", err))
					continue
				}

				evt := &api.Event{Height: height, TxHash: txHash, AllowanceChange: &e}
				events = append(events, evt)
			default:
				errs = errors.Join(errs, fmt.Errorf("staking: unknown event type: key: %s, val: %s", key, val))
			}
		}
	}

	return events, errs
}
