package churp

import beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"

// RPCMethodInit is the name of the `init` method.
var RPCMethodInit = "churp/init"

// InitRequest represents an initialization request.
type InitRequest struct {
	Identity

	// Epoch is the epoch of the handoff for which the node would
	// like to register.
	Epoch beacon.EpochTime `json:"epoch,omitempty"`
}
