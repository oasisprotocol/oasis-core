package p2p

import (
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

// KeyManagerProtocolID is a unique protocol identifier for the keymanager protocol.
const KeyManagerProtocolID = "keymanager"

// KeyManagerProtocolVersion is the supported version of the keymanager protocol.
var KeyManagerProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

// Constants related to the GetDiff method.
const (
	MethodCallEnclave     = "CallEnclave"
	MaxCallEnclaveRetries = 15
)

// CallEnclaveRequest is a CallEnclave request.
type CallEnclaveRequest struct {
	Data []byte `json:"data"`
}

// CallEnclaveResponse is a response to a CallEnclave request.
type CallEnclaveResponse struct {
	Data []byte `json:"data"`
}
