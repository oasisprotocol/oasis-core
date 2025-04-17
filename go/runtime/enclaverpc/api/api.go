// Package api defines the EnclaveRPC interface.
package api

import "github.com/oasisprotocol/oasis-core/go/common/cbor"

// Kind is the RPC call kind.
type Kind uint8

// Supported RPC call kinds.
const (
	KindNoiseSession  Kind = 0
	KindInsecureQuery Kind = 1
	KindLocalQuery    Kind = 2
)

// String returns a string representation of RPC call kind.
func (k Kind) String() string {
	switch k {
	case KindNoiseSession:
		return "noise session"
	case KindInsecureQuery:
		return "insecure query"
	case KindLocalQuery:
		return "local query"
	default:
		return "[unknown]"
	}
}

// Frame is an EnclaveRPC frame.
//
// It is the Go analog of the Rust RPC frame defined in runtime/src/enclave_rpc/types.rs.
type Frame struct {
	Session            []byte `json:"session,omitempty"`
	UntrustedPlaintext string `json:"untrusted_plaintext,omitempty"`
	Payload            []byte `json:"payload,omitempty"`
}

// Request is an EnclaveRPC request.
type Request struct {
	Method string          `json:"method"`
	Args   cbor.RawMessage `json:"args"`
}

// Body is an EnclaveRPC response body.
type Body struct {
	Success cbor.RawMessage `json:",omitempty"`
	Error   *string         `json:",omitempty"`
}

// Response is an EnclaveRPC response.
type Response struct {
	Body Body `json:"body"`
}

// Message is an EnclaveRPC protocol message.
type Message struct {
	Response *Response `json:"response"`
}

// PeerFeedback is the feedback on the peer that handled the last RPC call.
type PeerFeedback uint8

const (
	PeerFeedbackSuccess PeerFeedback = 0
	PeerFeedbackFailure PeerFeedback = 1
	PeerFeedbackBadPeer PeerFeedback = 2
)

// String returns a string representation of peer feedback.
func (pf PeerFeedback) String() string {
	switch pf {
	case PeerFeedbackSuccess:
		return "success"
	case PeerFeedbackFailure:
		return "failure"
	case PeerFeedbackBadPeer:
		return "bad peer"
	default:
		return "[unknown]"
	}
}
