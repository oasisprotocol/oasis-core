package protocol

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	roothash "github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

// NOTE: Bump RuntimeProtocol version in go/common/version if you
//       change any of the structures below.

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
	WorkerInfoRequest                    *Empty
	WorkerInfoResponse                   *WorkerInfoResponse
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
	WorkerLocalRPCCallRequest            *WorkerLocalRPCCallRequest
	WorkerLocalRPCCallResponse           *WorkerLocalRPCCallResponse
	WorkerCheckTxBatchRequest            *WorkerCheckTxBatchRequest
	WorkerCheckTxBatchResponse           *WorkerCheckTxBatchResponse
	WorkerExecuteTxBatchRequest          *WorkerExecuteTxBatchRequest
	WorkerExecuteTxBatchResponse         *WorkerExecuteTxBatchResponse
	WorkerAbortRequest                   *Empty
	WorkerAbortResponse                  *Empty

	// Host interface.
	HostRPCCallRequest                *HostRPCCallRequest
	HostRPCCallResponse               *HostRPCCallResponse
	HostStorageSyncGetSubtreeRequest  *HostStorageSyncGetSubtreeRequest
	HostStorageSyncGetPathRequest     *HostStorageSyncGetPathRequest
	HostStorageSyncGetNodeRequest     *HostStorageSyncGetNodeRequest
	HostStorageSyncGetValueRequest    *HostStorageSyncGetValueRequest
	HostStorageSyncSerializedResponse *HostStorageSyncSerializedResponse
	HostLocalStorageGetRequest        *HostLocalStorageGetRequest
	HostLocalStorageGetResponse       *HostLocalStorageGetResponse
	HostLocalStorageSetRequest        *HostLocalStorageSetRequest
	HostLocalStorageSetResponse       *Empty
}

// Empty is an empty message body.
type Empty struct {
}

// Error is a message body representing an error.
type Error struct {
	Message string `codec:"message"`
}

// WorkerInfoResponse is a worker info response message body.
type WorkerInfoResponse struct {
	// ProtocolVersion is the runtime protocol version supported by the worker.
	ProtocolVersion uint64 `codec:"protocol_version"`
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
	// Batch of storage write operations.
	WriteLog storage.WriteLog `codec:"write_log"`
	// New state root hash.
	NewStateRoot hash.Hash `codec:"new_state_root"`
}

// WorkerLocalRPCCallRequest is a worker local RPC call request message body.
type WorkerLocalRPCCallRequest struct {
	// Request.
	Request []byte `codec:"request"`
	// State root hash.
	StateRoot hash.Hash `codec:"state_root"`
}

// WorkerLocalRPCCallResponse is a worker local RPC call response message body.
type WorkerLocalRPCCallResponse struct {
	// Response.
	Response []byte `codec:"response"`
}

// WorkerCheckTxBatchRequest is a worker check tx batch request message body.
type WorkerCheckTxBatchRequest struct {
	// Batch of runtime inputs to check.
	Inputs runtime.Batch `codec:"inputs"`
	// Block on which the batch check should be based.
	Block roothash.Block `codec:"block"`
}

// WorkerCheckTxBatchResponse is a worker check tx batch response message body.
type WorkerCheckTxBatchResponse struct {
	// Batch of runtime check results.
	Results runtime.Batch `codec:"results"`
}

// ComputedBatch is a computed batch.
type ComputedBatch struct {
	// Header is the compute results header.
	Header commitment.ComputeResultsHeader `codec:"header"`
	// Log that generates the I/O tree.
	IOWriteLog storage.WriteLog `codec:"io_write_log"`
	// Batch of storage write operations.
	StateWriteLog storage.WriteLog `codec:"state_write_log"`
	// If this runtime uses a TEE, then this is the signature of Header with
	// node's RAK for this runtime.
	RakSig signature.RawSignature `codec:"rak_sig"`
}

// String returns a string representation of a computed batch.
func (b *ComputedBatch) String() string {
	return "<ComputedBatch>"
}

// WorkerExecuteTxBatchRequest is a worker execute tx batch request message body.
type WorkerExecuteTxBatchRequest struct {
	// IORoot is the I/O root containing the inputs (transactions) that
	// the compute node should use. It must match what is passed in "inputs".
	IORoot hash.Hash `codec:"io_root"`
	// Batch of inputs (transactions).
	Inputs runtime.Batch `codec:"inputs"`
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

// HostStorageSyncGetSubtreeRequest is a host storage read syncer get subtree request message body.
type HostStorageSyncGetSubtreeRequest struct {
	RootHash  hash.Hash `codec:"root_hash"`
	NodePath  hash.Hash `codec:"node_path"`
	NodeDepth uint8     `codec:"node_depth"`
	MaxDepth  uint8     `codec:"max_depth"`
}

// HostStorageSyncGetPathRequest is a host storage read syncer get path request message body.
type HostStorageSyncGetPathRequest struct {
	RootHash   hash.Hash `codec:"root_hash"`
	Key        hash.Hash `codec:"key"`
	StartDepth uint8     `codec:"start_depth"`
}

// HostStorageSyncGetNodeRequest is a host storage read syncer get node request message body.
type HostStorageSyncGetNodeRequest struct {
	RootHash  hash.Hash `codec:"root_hash"`
	NodePath  hash.Hash `codec:"node_path"`
	NodeDepth uint8     `codec:"node_depth"`
}

// HostStorageSyncGetValueRequest is a host storage read syncer get value message body.
type HostStorageSyncGetValueRequest struct {
	RootHash hash.Hash `codec:"root_hash"`
	ValueID  hash.Hash `codec:"value_id"`
}

// HostStorageSyncSerializedResponse is a host storage read syncer response body containing serialized data.
type HostStorageSyncSerializedResponse struct {
	Serialized []byte `codec:"serialized"`
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
