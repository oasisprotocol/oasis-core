// Package api defines the roothash application API for other applications.
package api

type messageKind uint8

// RuntimeMessageNoop is the message kind used when dispatching Noop runtime messages.
var RuntimeMessageNoop = messageKind(0)
