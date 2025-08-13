package vault

import (
	"errors"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"

	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// EventsFromCometBFT extracts vault events from CometBFT events.
func EventsFromCometBFT(height int64, tmEvents []cmtabcitypes.Event) ([]*vault.Event, error) {
	var events []*vault.Event
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the vault app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			evt := &vault.Event{Height: height}
			switch {
			case eventsAPI.IsAttributeKind(key, &vault.ActionSubmittedEvent{}):
				// Action submitted event.
				var e vault.ActionSubmittedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionSubmitted event: %w", err))
					continue
				}

				evt.ActionSubmitted = &e
			case eventsAPI.IsAttributeKind(key, &vault.ActionCanceledEvent{}):
				// Action canceled event.
				var e vault.ActionCanceledEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionCanceled event: %w", err))
					continue
				}

				evt.ActionCanceled = &e
			case eventsAPI.IsAttributeKind(key, &vault.ActionExecutedEvent{}):
				// Action executed event.
				var e vault.ActionExecutedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt ActionExecuted event: %w", err))
					continue
				}

				evt.ActionExecuted = &e
			case eventsAPI.IsAttributeKind(key, &vault.StateChangedEvent{}):
				// State changed event.
				var e vault.StateChangedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt StateChanged event: %w", err))
					continue
				}

				evt.StateChanged = &e
			case eventsAPI.IsAttributeKind(key, &vault.PolicyUpdatedEvent{}):
				// Policy updated event.
				var e vault.PolicyUpdatedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt PolicyUpdated event: %w", err))
					continue
				}

				evt.PolicyUpdated = &e
			case eventsAPI.IsAttributeKind(key, &vault.AuthorityUpdatedEvent{}):
				// Action submitted event.
				var e vault.AuthorityUpdatedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("vault: corrupt AuthorityUpdated event: %w", err))
					continue
				}

				evt.AuthorityUpdated = &e
			default:
				errs = errors.Join(errs, fmt.Errorf("vault: unknown event type: key: %s, val: %s", key, val))
				continue
			}

			events = append(events, evt)
		}
	}

	return events, errs
}
