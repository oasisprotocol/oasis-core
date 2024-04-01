package churp

import beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"

// RPCMethodInit is the name of the `init` method.
var RPCMethodInit = "churp/init"

// HandoffRequest represents a handoff request.
type HandoffRequest struct {
	Identity

	// Epoch is the epoch of the handoff.
	Epoch beacon.EpochTime `json:"epoch,omitempty"`
}
