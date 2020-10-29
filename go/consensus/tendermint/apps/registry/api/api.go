// Package api defines the registry application API for other applications.
package api

type messageKind uint8

// MessageNewRuntimeRegistered is the message kind for new runtime registrations. The message is
// the runtime descriptor of the runtime that has been registered.
//
// The message is not emitted for runtime descriptor updates.
var MessageNewRuntimeRegistered = messageKind(0)
