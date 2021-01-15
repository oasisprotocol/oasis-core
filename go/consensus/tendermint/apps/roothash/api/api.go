// Package api defines the roothash application API for other applications.
package api

type messageKind uint8

var (
	// RuntimeMessageNoop is the message kind used when dispatching Noop runtime messages.
	RuntimeMessageNoop = messageKind(0)

	// RuntimeMessageStaking is the message kind used when dispatching Staking runtime messages.
	RuntimeMessageStaking = messageKind(1)

	// RuntimeMessageRegistry is the message kind used when dispatching Registry runtime messages.
	RuntimeMessageRegistry = messageKind(2)
)
