package rpc

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
)

// ModuleName is a unique module name for the P2P RPC module.
const ModuleName = "p2p/rpc"

var (
	// ErrMethodNotSupported is an error raised when a given method is not supported.
	ErrMethodNotSupported = errors.New(ModuleName, 1, "rpc: method not supported")

	// ErrBadRequest is an error raised when a given request is malformed.
	ErrBadRequest = errors.New(ModuleName, 2, "rpc: bad request")
)

// Request is a request sent by the client.
type Request struct {
	// Method is the name of the method.
	Method string `json:"method"`
	// Body is the method-specific body.
	Body cbor.RawMessage `json:"body"`
}

// Error is a message body representing an error.
type Error struct {
	Module  string `json:"module,omitempty"`
	Code    uint32 `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// String returns a string representation of this error.
func (e Error) String() string {
	return fmt.Sprintf("error: module: %s code: %d message: %s", e.Module, e.Code, e.Message)
}

// Response is a response to a previously sent request.
type Response struct {
	// Ok is the method-specific response in case of success.
	Ok cbor.RawMessage `json:"ok,omitempty"`
	// Error is an error response in case of failure.
	Error *Error `json:"error,omitempty"`
}
