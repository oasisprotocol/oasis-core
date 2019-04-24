package protocol

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	roothash "github.com/oasislabs/ekiden/go/roothash/api/block"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

// MessageType is a message type.
type MessageType uint8

// String returns a string representation of a message type.
func (m MessageType) String() string {
	switch m {
	case MessageRequest:
		return "request"
	case MessageResponse:
		return "response"
	default:
		return "invalid"
	}
}

const (
	// Invalid message (should never be seen on the wire).
	MessageInvalid MessageType = 0

	// Request message.
	MessageRequest MessageType = 1

	// Response message.
	MessageResponse MessageType = 2
)

// Message is a protocol message.
type Message struct {
	ID          uint64      `codec:"id"`
	MessageType MessageType `codec:"message_type"`
	Body        Body        `codec:"body"`
	SpanContext []byte      `codec:"span_context"`
}

// Body is a protocol message body.
type Body struct {
	_struct struct{} `codec:",omitempty"` // nolint

	Empty *Empty
	Error *Error

	// Worker interface.
	WorkerPingRequest                    *Empty
	WorkerShutdownRequest                *Empty
	WorkerCapabilityTEERakInitRequest    *WorkerCapabilityTEERakInitRequest
	WorkerCapabilityTEERakInitResponse   *Empty
	WorkerCapabilityTEERakReportRequest  *Empty
	WorkerCapabilityTEERakReportResponse *WorkerCapabilityTEERakReportResponse
	WorkerCapabilityTEERakAvrRequest     *WorkerCapabilityTEERakAvrRequest
	WorkerCapabilityTEERakAvrResponse    *Empty
	WorkerRPCCallRequest                 *WorkerRPCCallRequest
	WorkerRPCCallResponse                *WorkerRPCCallResponse
	WorkerExecuteTxBatchRequest          *WorkerExecuteTxBatchRequest
	WorkerExecuteTxBatchResponse         *WorkerExecuteTxBatchResponse
	WorkerAbortRequest                   *Empty
	WorkerAbortResponse                  *Empty

	// Host interface.
	HostRPCCallRequest          *HostRPCCallRequest
	HostRPCCallResponse         *HostRPCCallResponse
	HostStorageGetRequest       *HostStorageGetRequest
	HostStorageGetResponse      *HostStorageGetResponse
	HostStorageGetBatchRequest  *HostStorageGetBatchRequest
	HostStorageGetBatchResponse *HostStorageGetBatchResponse
	HostLocalStorageGetRequest  *HostLocalStorageGetRequest
	HostLocalStorageGetResponse *HostLocalStorageGetResponse
	HostLocalStorageSetRequest  *HostLocalStorageSetRequest
	HostLocalStorageSetResponse *Empty
}

// Empty is an empty message body.
type Empty struct {
}

// Error is a message body representing an error.
type Error struct {
	Message string `codec:"message"`
}

// WorkerCapabilityTEERakInitRequest is a worker RFC 0009 CapabilityTEE
// initialization request message body.
type WorkerCapabilityTEERakInitRequest struct {
	TargetInfo []byte `codec:"target_info"`
}

// WorkerCapabilityTEERakReportResponse is a worker RFC 0009 CapabilityTEE RAK response message body.
type WorkerCapabilityTEERakReportResponse struct {
	RakPub signature.PublicKey `codec:"rak_pub"`
	Report []byte              `codec:"report"`
	Nonce  string              `codec:"nonce"`
}

// WorkerCapabilityTEERakAvrRequest is a worker RFC 0009 CapabilityTEE RAK AVR setup request message body.
type WorkerCapabilityTEERakAvrRequest struct {
	AVR ias.AVRBundle `codec:"avr"`
}

// WorkerRPCCallRequest is a worker RPC call request message body.
type WorkerRPCCallRequest struct {
	// Request.
	Request []byte `codec:"request"`
	// State root hash.
	StateRoot hash.Hash `codec:"state_root"`
}

// WorkerRPCCallResponse is a worker RPC call response message body.
type WorkerRPCCallResponse struct {
	// Response.
	Response []byte `codec:"response"`
	// Batch of storage inserts.
	StorageInserts []storage.Value `codec:"storage_inserts"`
	// New state root hash.
	NewStateRoot hash.Hash `codec:"new_state_root"`
}

// ComputedBatch is a computed batch.
type ComputedBatch struct {
	// Batch of runtime outputs.
	Outputs runtime.Batch `codec:"outputs"`
	// Batch of storage inserts.
	StorageInserts []storage.Value `codec:"storage_inserts"`
	// New state root hash.
	NewStateRoot hash.Hash `codec:"new_state_root"`
	// Tags are runtime-specific indexable tags.
	Tags []runtime.Tag `codec:"tags"`
	// If this runtime uses a TEE, then this is the signature of the batch's
	// BatchSigMessage with the node's RAK for this runtime.
	RakSig signature.RawSignature `codec:"rak_sig"`
}

// String returns a string representation of a computed batch.
func (b *ComputedBatch) String() string {
	return "<ComputedBatch>"
}

// WorkerExecuteTxBatchRequest is a worker execute tx batch request message body.
type WorkerExecuteTxBatchRequest struct {
	// Batch of runtime calls.
	Calls runtime.Batch `codec:"calls"`
	// Block on which the batch computation should be based.
	Block roothash.Block `codec:"block"`
}

// WorkerExecuteTxBatchResponse is a worker execute tx batch response message body.
type WorkerExecuteTxBatchResponse struct {
	Batch ComputedBatch `codec:"batch"`
}

const (
	// EndpointKeyManager is a key manager client endpoint.
	EndpointKeyManager string = "key-manager"
)

// HostRPCCallRequest is a host RPC call request message body.
type HostRPCCallRequest struct {
	Endpoint string `codec:"endpoint"`
	Request  []byte `codec:"request"`
}

// HostRPCCallResponse is a host RPC call response message body.
type HostRPCCallResponse struct {
	Response []byte `codec:"response"`
}

// HostStorageGetRequest is a host storage get request message body.
type HostStorageGetRequest struct {
	Key storage.Key `codec:"key"`
}

// HostStorageGetResponse is a host storage get response message body.
type HostStorageGetResponse struct {
	Value []byte `codec:"value"`
}

// HostStorageGetBatchRequest is a host storage batch get request message body.
type HostStorageGetBatchRequest struct {
	Keys []storage.Key `codec:"keys"`
}

// HostStorageGetBatchResponse is a host storage batch get response message body.
type HostStorageGetBatchResponse struct {
	Values [][]byte `codec:"values"`
}

// HostLocalStorageGetRequest is a host local storage get request message body.
type HostLocalStorageGetRequest struct {
	Key []byte `codec:"key"`
}

// HostLocalStorageGetResponse is a host local storage get response message body.
type HostLocalStorageGetResponse struct {
	Value []byte `codec:"value"`
}

// HostLocalStorageSetRequest is a host local storage set request message body.
type HostLocalStorageSetRequest struct {
	Key   []byte `codec:"key"`
	Value []byte `codec:"value"`
}
