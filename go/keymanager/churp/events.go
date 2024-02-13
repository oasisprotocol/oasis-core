package churp

import "github.com/oasisprotocol/oasis-core/go/consensus/api/events"

var (
	// eventNameCreate is the event name for create events.
	eventNameCreate = events.NewEventName(ModuleName, "create")

	// eventNameUpdate is the event name for update events.
	eventNameUpdate = events.NewEventName(ModuleName, "update")
)

// CreateEvent is the key manager CHURP create event.
type CreateEvent struct {
	Status *Status
}

// EventKind returns a string representation of this event's kind.
func (ev *CreateEvent) EventKind() string {
	return eventNameCreate
}

// UpdateEvent is the key manager CHURP update event.
type UpdateEvent struct {
	Status *Status
}

// EventKind returns a string representation of this event's kind.
func (ev *UpdateEvent) EventKind() string {
	return eventNameUpdate
}
