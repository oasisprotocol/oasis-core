// Package api defines the EnclaveRPC interface.
package api

// Frame is an EnclaveRPC frame.
//
// It is the Go analog of the Rust RPC frame defined in runtime/src/enclave_rpc/types.rs.
type Frame struct {
	Session            []byte `json:"session,omitempty"`
	UntrustedPlaintext string `json:"untrusted_plaintext,omitempty"`
	Payload            []byte `json:"payload,omitempty"`
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
