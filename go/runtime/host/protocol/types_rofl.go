package protocol

import (
	"github.com/oasisprotocol/oasis-core/go/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

// HostSubmitTxRequest is a request to host to submit a runtime transaction.
type HostSubmitTxRequest struct {
	// RuntimeID is the identifier of the target runtime.
	RuntimeID common.Namespace `json:"runtime_id"`
	// Data is the raw transaction data.
	Data []byte `json:"data"`
	// Wait specifies whether the call should wait until the transaction is included in a block.
	Wait bool `json:"wait,omitempty"`
	// Prove specifies whether the response should include a proof of transaction being included in
	// a block.
	Prove bool `json:"prove,omitempty"`
}

// HostSubmitTxResponse is a response from host on transaction submission.
type HostSubmitTxResponse struct {
	// Output is the transaction output.
	Output []byte `json:"output,omitempty"`
	// Round is the roothash round in which the transaction was executed.
	Round uint64 `json:"round,omitempty"`
	// BatchOrder is the order of the transaction in the execution batch.
	BatchOrder uint32 `json:"batch_order,omitempty"`
	// Proof is an optional inclusion proof.
	Proof *storage.Proof `json:"proof,omitempty"`
}

// HostRegisterNotifyRequest is a request to host to register for notifications.
type HostRegisterNotifyRequest struct {
	// RuntimeBlock subscribes to runtime block notifications.
	RuntimeBlock bool `json:"runtime_block,omitempty"`
	// RuntimeEvent subscribes to runtime event emission notifications.
	RuntimeEvent *struct {
		// Tags specifies which event tags to subscribe to.
		Tags [][]byte `json:"tags,omitempty"`
	} `json:"runtime_event,omitempty"`
}

// RuntimeNotifyEvent is an event notification.
type RuntimeNotifyEvent struct {
	// Block is the block header of the block that emitted the event.
	Block *roothash.AnnotatedBlock `json:"block"`
	// Tags are the matching tags that were emitted.
	Tags [][]byte `json:"tags"`
}

// RuntimeNotifyRequest is a notification from the host.
type RuntimeNotifyRequest struct {
	// RuntimeBlock notifies about a new runtime block.
	RuntimeBlock *roothash.AnnotatedBlock `json:"runtime_block,omitempty"`
	// RuntimeEvent notifies about a specific runtime event being emitted.
	RuntimeEvent *RuntimeNotifyEvent `json:"runtime_event,omitempty"`
}
