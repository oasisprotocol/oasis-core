package registry

import (
	"errors"
	"fmt"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"

	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	"github.com/oasisprotocol/oasis-core/go/registry/api"
)

// EventsFromCometBFT extracts registry events from CometBFT events.
func EventsFromCometBFT(height int64, tmEvents []cmtabcitypes.Event) ([]*api.Event, []*NodeListEpochInternalEvent, error) {
	var events []*api.Event
	var nodeListEvents []*NodeListEpochInternalEvent
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the registry app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case eventsAPI.IsAttributeKind(key, &api.NodeListEpochEvent{}):
				// Node list epoch event (value is ignored).
				nodeListEvents = append(nodeListEvents, &NodeListEpochInternalEvent{Height: height})
			case eventsAPI.IsAttributeKind(key, &api.RuntimeStartedEvent{}):
				// Runtime started event.
				var e api.RuntimeStartedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt RuntimeStarted event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, RuntimeStartedEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.RuntimeSuspendedEvent{}):
				// Runtime suspended event.
				var e api.RuntimeSuspendedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt RuntimeSuspended event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, RuntimeSuspendedEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.EntityEvent{}):
				// Entity event.
				var e api.EntityEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt Entity event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, EntityEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.NodeEvent{}):
				// Node event.
				var e api.NodeEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt Node event: %w", err))
					continue
				}

				events = append(events, &api.Event{Height: height, NodeEvent: &e})
			case eventsAPI.IsAttributeKind(key, &api.NodeUnfrozenEvent{}):
				// Node unfrozen event.
				var e api.NodeUnfrozenEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("registry: corrupt NodeUnfrozen event: %w", err))
					continue
				}
				events = append(events, &api.Event{Height: height, NodeUnfrozenEvent: &e})
			}
		}
	}
	return events, nodeListEvents, errs
}
