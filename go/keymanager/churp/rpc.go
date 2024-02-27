package churp

// RPCMethodInit is the name of the `init` method.
var RPCMethodInit = "churp/init"

// InitRequest represents an initialization request.
type InitRequest struct {
	Identity

	// Round is the round for which the node would like to register.
	Round uint64 `json:"round,omitempty"`
}
