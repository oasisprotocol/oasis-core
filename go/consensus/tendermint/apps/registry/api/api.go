// Package api defines the registry application API for other applications.
package api

type messageKind uint8

var (
	// MessageNewRuntimeRegistered is the message kind for new runtime registrations. The message is
	// the runtime descriptor of the runtime that has been registered.
	//
	// The message is not emitted for runtime descriptor updates.
	MessageNewRuntimeRegistered = messageKind(0)

	// MessageRuntimeUpdated is the message kind for runtime registration updates. The message is
	// the runtime descriptor of the runtime that has been updated. Any errors returned from the
	// handler will prevent the runtime update from taking place.
	//
	// The message is also emitted for new runtime registrations.
	MessageRuntimeUpdated = messageKind(1)

	// MessageRuntimeResumed is the message kind for suspended runtime resumptions. The message is
	// the runtime descriptor of the runtime that has been resumed.
	MessageRuntimeResumed = messageKind(2)
)
