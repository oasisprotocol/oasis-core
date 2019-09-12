package protocol

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	roothash "github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
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
	ID          uint64      `json:"id"`
	MessageType MessageType `json:"message_type"`
	Body        Body        `json:"body"`
	SpanContext []byte      `json:"span_context"`
}

// Body is a protocol message body.
type Body struct {
	Empty *Empty `json:",omitempty"`
	Error *Error `json:",omitempty"`

	// Worker interface.
	WorkerInfoRequest                    *Empty                                `json:",omitempty"`
	WorkerInfoResponse                   *WorkerInfoResponse                   `json:",omitempty"`
	WorkerPingRequest                    *Empty                                `json:",omitempty"`
	WorkerShutdownRequest                *Empty                                `json:",omitempty"`
	WorkerCapabilityTEERakInitRequest    *WorkerCapabilityTEERakInitRequest    `json:",omitempty"`
	WorkerCapabilityTEERakInitResponse   *Empty                                `json:",omitempty"`
	WorkerCapabilityTEERakReportRequest  *Empty                                `json:",omitempty"`
	WorkerCapabilityTEERakReportResponse *WorkerCapabilityTEERakReportResponse `json:",omitempty"`
	WorkerCapabilityTEERakAvrRequest     *WorkerCapabilityTEERakAvrRequest     `json:",omitempty"`
	WorkerCapabilityTEERakAvrResponse    *Empty                                `json:",omitempty"`
	WorkerRPCCallRequest                 *WorkerRPCCallRequest                 `json:",omitempty"`
	WorkerRPCCallResponse                *WorkerRPCCallResponse                `json:",omitempty"`
	WorkerLocalRPCCallRequest            *WorkerLocalRPCCallRequest            `json:",omitempty"`
	WorkerLocalRPCCallResponse           *WorkerLocalRPCCallResponse           `json:",omitempty"`
	WorkerCheckTxBatchRequest            *WorkerCheckTxBatchRequest            `json:",omitempty"`
	WorkerCheckTxBatchResponse           *WorkerCheckTxBatchResponse           `json:",omitempty"`
	WorkerExecuteTxBatchRequest          *WorkerExecuteTxBatchRequest          `json:",omitempty"`
	WorkerExecuteTxBatchResponse         *WorkerExecuteTxBatchResponse         `json:",omitempty"`
	WorkerAbortRequest                   *Empty                                `json:",omitempty"`
	WorkerAbortResponse                  *Empty                                `json:",omitempty"`

	// Host interface.
	HostKeyManagerPolicyRequest  *HostKeyManagerPolicyRequest  `json:",omitempty"`
	HostKeyManagerPolicyResponse *HostKeyManagerPolicyResponse `json:",omitempty"`
	HostRPCCallRequest           *HostRPCCallRequest           `json:",omitempty"`
	HostRPCCallResponse          *HostRPCCallResponse          `json:",omitempty"`
	HostStorageSyncRequest       *HostStorageSyncRequest       `json:",omitempty"`
	HostStorageSyncResponse      *HostStorageSyncResponse      `json:",omitempty"`
	HostLocalStorageGetRequest   *HostLocalStorageGetRequest   `json:",omitempty"`
	HostLocalStorageGetResponse  *HostLocalStorageGetResponse  `json:",omitempty"`
	HostLocalStorageSetRequest   *HostLocalStorageSetRequest   `json:",omitempty"`
	HostLocalStorageSetResponse  *Empty                        `json:",omitempty"`
}

// Empty is an empty message body.
type Empty struct {
}

// Error is a message body representing an error.
type Error struct {
	Message string `json:"message"`
}

// WorkerInfoResponse is a worker info response message body.
type WorkerInfoResponse struct {
	// ProtocolVersion is the runtime protocol version supported by the worker.
	ProtocolVersion uint64 `json:"protocol_version"`

	// RuntimeVersion is the version of the runtime.
	RuntimeVersion uint64 `json:"runtime_version"`
}

// WorkerCapabilityTEERakInitRequest is a worker RFC 0009 CapabilityTEE
// initialization request message body.
type WorkerCapabilityTEERakInitRequest struct {
	TargetInfo []byte `json:"target_info"`
}

// WorkerCapabilityTEERakReportResponse is a worker RFC 0009 CapabilityTEE RAK response message body.
type WorkerCapabilityTEERakReportResponse struct {
	RakPub signature.PublicKey `json:"rak_pub"`
	Report []byte              `json:"report"`
	Nonce  string              `json:"nonce"`
}

// WorkerCapabilityTEERakAvrRequest is a worker RFC 0009 CapabilityTEE RAK AVR setup request message body.
type WorkerCapabilityTEERakAvrRequest struct {
	AVR ias.AVRBundle `json:"avr"`
}

// WorkerRPCCallRequest is a worker RPC call request message body.
type WorkerRPCCallRequest struct {
	// Request.
	Request []byte `json:"request"`
	// State root hash.
	StateRoot hash.Hash `json:"state_root"`
}

// WorkerRPCCallResponse is a worker RPC call response message body.
type WorkerRPCCallResponse struct {
	// Response.
	Response []byte `json:"response"`
	// Batch of storage write operations.
	WriteLog storage.WriteLog `json:"write_log"`
	// New state root hash.
	NewStateRoot hash.Hash `json:"new_state_root"`
}

// WorkerLocalRPCCallRequest is a worker local RPC call request message body.
type WorkerLocalRPCCallRequest struct {
	// Request.
	Request []byte `json:"request"`
	// State root hash.
	StateRoot hash.Hash `json:"state_root"`
}

// WorkerLocalRPCCallResponse is a worker local RPC call response message body.
type WorkerLocalRPCCallResponse struct {
	// Response.
	Response []byte `json:"response"`
}

// WorkerCheckTxBatchRequest is a worker check tx batch request message body.
type WorkerCheckTxBatchRequest struct {
	// Batch of runtime inputs to check.
	Inputs transaction.RawBatch `json:"inputs"`
	// Block on which the batch check should be based.
	Block roothash.Block `json:"block"`
}

// WorkerCheckTxBatchResponse is a worker check tx batch response message body.
type WorkerCheckTxBatchResponse struct {
	// Batch of runtime check results.
	Results transaction.RawBatch `json:"results"`
}

// ComputedBatch is a computed batch.
type ComputedBatch struct {
	// Header is the compute results header.
	Header commitment.ComputeResultsHeader `json:"header"`
	// Log that generates the I/O tree.
	IOWriteLog storage.WriteLog `json:"io_write_log"`
	// Batch of storage write operations.
	StateWriteLog storage.WriteLog `json:"state_write_log"`
	// If this runtime uses a TEE, then this is the signature of Header with
	// node's RAK for this runtime.
	RakSig signature.RawSignature `json:"rak_sig"`
}

// String returns a string representation of a computed batch.
func (b *ComputedBatch) String() string {
	return "<ComputedBatch>"
}

// WorkerExecuteTxBatchRequest is a worker execute tx batch request message body.
type WorkerExecuteTxBatchRequest struct {
	// IORoot is the I/O root containing the inputs (transactions) that
	// the compute node should use. It must match what is passed in "inputs".
	IORoot hash.Hash `json:"io_root"`
	// Batch of inputs (transactions).
	Inputs transaction.RawBatch `json:"inputs"`
	// Block on which the batch computation should be based.
	Block roothash.Block `json:"block"`
}

// WorkerExecuteTxBatchResponse is a worker execute tx batch response message body.
type WorkerExecuteTxBatchResponse struct {
	Batch ComputedBatch `json:"batch"`
}

const (
	// EndpointKeyManager is a key manager client endpoint.
	EndpointKeyManager string = "key-manager"
)

// HostKeyManagerPolicyRequest is a host key manager policy request message body.
type HostKeyManagerPolicyRequest struct {
}

// HostKeyManagerPolicyResponse is a host key manager policy response message body.
type HostKeyManagerPolicyResponse struct {
	SignedPolicyRaw []byte `json:"signed_policy_raw"`
}

// HostRPCCallRequest is a host RPC call request message body.
type HostRPCCallRequest struct {
	Endpoint string `json:"endpoint"`
	Request  []byte `json:"request"`
}

// HostRPCCallResponse is a host RPC call response message body.
type HostRPCCallResponse struct {
	Response []byte `json:"response"`
}

// HostStorageSyncRequest is a host storage read syncer request message body.
type HostStorageSyncRequest struct {
	SyncGet         *storage.GetRequest         `json:",omitempty"`
	SyncGetPrefixes *storage.GetPrefixesRequest `json:",omitempty"`
	SyncIterate     *storage.IterateRequest     `json:",omitempty"`
}

// HostStorageSyncResponse is a host storage read syncer response body.
type HostStorageSyncResponse struct {
	ProofResponse *storage.ProofResponse `json:",omitempty"`
}

// HostLocalStorageGetRequest is a host local storage get request message body.
type HostLocalStorageGetRequest struct {
	Key []byte `json:"key"`
}

// HostLocalStorageGetResponse is a host local storage get response message body.
type HostLocalStorageGetResponse struct {
	Value []byte `json:"value"`
}

// HostLocalStorageSetRequest is a host local storage set request message body.
type HostLocalStorageSetRequest struct {
	Key   []byte `json:"key"`
	Value []byte `json:"value"`
}
