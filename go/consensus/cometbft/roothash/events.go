package roothash

import (
	"errors"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

// EventsFromCometBFT extracts roothash events from CometBFT events.
func EventsFromCometBFT(
	height int64,
	tmEvents []cmtabcitypes.Event,
) ([]*roothash.Event, error) {
	var events []*roothash.Event
	var errs error
EventLoop:
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the roothash app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		var (
			runtimeID *common.Namespace
			ev        *roothash.Event
		)
		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case eventsAPI.IsAttributeKind(key, &roothash.FinalizedEvent{}):
				// Finalized event.
				var e roothash.FinalizedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt Finalized event: %w", err))
					continue EventLoop
				}

				ev = &roothash.Event{Finalized: &e}
			case eventsAPI.IsAttributeKind(key, &roothash.ExecutionDiscrepancyDetectedEvent{}):
				// An execution discrepancy has been detected.
				var e roothash.ExecutionDiscrepancyDetectedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt ExecutionDiscrepancyDetected event: %w", err))
					continue EventLoop
				}

				ev = &roothash.Event{ExecutionDiscrepancyDetected: &e}
			case eventsAPI.IsAttributeKind(key, &roothash.ExecutorCommittedEvent{}):
				// An executor commit has been processed.
				var e roothash.ExecutorCommittedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt ExecutorCommitted event: %w", err))
					continue EventLoop
				}

				ev = &roothash.Event{ExecutorCommitted: &e}
			case eventsAPI.IsAttributeKind(key, &roothash.InMsgProcessedEvent{}):
				// Incoming message processed event.
				var e roothash.InMsgProcessedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt InMsgProcessed event: %w", err))
					continue EventLoop
				}

				ev = &roothash.Event{InMsgProcessed: &e}
			case eventsAPI.IsAttributeKind(key, &roothash.RuntimeIDAttribute{}):
				if runtimeID != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: duplicate runtime ID attribute"))
					continue EventLoop
				}
				rtAttribute := roothash.RuntimeIDAttribute{}
				if err := eventsAPI.DecodeValue(val, &rtAttribute); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt runtime ID: %w", err))
					continue EventLoop
				}
				runtimeID = &rtAttribute.ID
			default:
				errs = errors.Join(errs, fmt.Errorf("roothash: unknown event type: key: %s, val: %s", key, val))
			}
		}

		if runtimeID == nil {
			errs = errors.Join(errs, fmt.Errorf("roothash: missing runtime ID attribute"))
			continue
		}
		if ev != nil {
			ev.RuntimeID = *runtimeID
			ev.Height = height
			events = append(events, ev)
		}
	}
	return events, errs
}
