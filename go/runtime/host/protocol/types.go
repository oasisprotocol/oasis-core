package protocol

import (
	"fmt"
	"reflect"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
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
		return fmt.Sprintf("[malformed: %d]", m)
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

	// Runtime interface.
	RuntimeInfoRequest                    *RuntimeInfoRequest                    `json:",omitempty"`
	RuntimeInfoResponse                   *RuntimeInfoResponse                   `json:",omitempty"`
	RuntimePingRequest                    *Empty                                 `json:",omitempty"`
	RuntimeShutdownRequest                *Empty                                 `json:",omitempty"`
	RuntimeCapabilityTEERakInitRequest    *RuntimeCapabilityTEERakInitRequest    `json:",omitempty"`
	RuntimeCapabilityTEERakInitResponse   *Empty                                 `json:",omitempty"`
	RuntimeCapabilityTEERakReportRequest  *Empty                                 `json:",omitempty"`
	RuntimeCapabilityTEERakReportResponse *RuntimeCapabilityTEERakReportResponse `json:",omitempty"`
	RuntimeCapabilityTEERakAvrRequest     *RuntimeCapabilityTEERakAvrRequest     `json:",omitempty"`
	RuntimeCapabilityTEERakAvrResponse    *Empty                                 `json:",omitempty"`
	RuntimeRPCCallRequest                 *RuntimeRPCCallRequest                 `json:",omitempty"`
	RuntimeRPCCallResponse                *RuntimeRPCCallResponse                `json:",omitempty"`
	RuntimeLocalRPCCallRequest            *RuntimeLocalRPCCallRequest            `json:",omitempty"`
	RuntimeLocalRPCCallResponse           *RuntimeLocalRPCCallResponse           `json:",omitempty"`
	RuntimeCheckTxBatchRequest            *RuntimeCheckTxBatchRequest            `json:",omitempty"`
	RuntimeCheckTxBatchResponse           *RuntimeCheckTxBatchResponse           `json:",omitempty"`
	RuntimeExecuteTxBatchRequest          *RuntimeExecuteTxBatchRequest          `json:",omitempty"`
	RuntimeExecuteTxBatchResponse         *RuntimeExecuteTxBatchResponse         `json:",omitempty"`
	RuntimeAbortRequest                   *Empty                                 `json:",omitempty"`
	RuntimeAbortResponse                  *Empty                                 `json:",omitempty"`
	RuntimeKeyManagerPolicyUpdateRequest  *RuntimeKeyManagerPolicyUpdateRequest  `json:",omitempty"`
	RuntimeKeyManagerPolicyUpdateResponse *Empty                                 `json:",omitempty"`

	// Host interface.
	HostRPCCallRequest          *HostRPCCallRequest          `json:",omitempty"`
	HostRPCCallResponse         *HostRPCCallResponse         `json:",omitempty"`
	HostStorageSyncRequest      *HostStorageSyncRequest      `json:",omitempty"`
	HostStorageSyncResponse     *HostStorageSyncResponse     `json:",omitempty"`
	HostLocalStorageGetRequest  *HostLocalStorageGetRequest  `json:",omitempty"`
	HostLocalStorageGetResponse *HostLocalStorageGetResponse `json:",omitempty"`
	HostLocalStorageSetRequest  *HostLocalStorageSetRequest  `json:",omitempty"`
	HostLocalStorageSetResponse *Empty                       `json:",omitempty"`
}

// Type returns the message type by determining the name of the first non-nil member.
func (body Body) Type() string {
	b := reflect.ValueOf(body)
	for i := 0; i < b.NumField(); i++ {
		if !b.Field(i).IsNil() {
			return reflect.TypeOf(body).Field(i).Name
		}
	}
	return ""
}

// Empty is an empty message body.
type Empty struct {
}

// Error is a message body representing an error.
type Error struct {
	Module  string `json:"module,omitempty"`
	Code    uint32 `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// RuntimeInfoRequest is a worker info request message body.
type RuntimeInfoRequest struct {
	// RuntimeID is the assigned runtime ID of the loaded runtime.
	RuntimeID common.Namespace `json:"runtime_id"`
}

// RuntimeInfoResponse is a worker info response message body.
type RuntimeInfoResponse struct {
	// ProtocolVersion is the runtime protocol version supported by the worker.
	ProtocolVersion uint64 `json:"protocol_version"`

	// RuntimeVersion is the version of the runtime.
	RuntimeVersion uint64 `json:"runtime_version"`
}

// RuntimeCapabilityTEERakInitRequest is a worker RFC 0009 CapabilityTEE
// initialization request message body.
type RuntimeCapabilityTEERakInitRequest struct {
	TargetInfo []byte `json:"target_info"`
}

// RuntimeCapabilityTEERakReportResponse is a worker RFC 0009 CapabilityTEE RAK response message body.
type RuntimeCapabilityTEERakReportResponse struct {
	RakPub signature.PublicKey `json:"rak_pub"`
	Report []byte              `json:"report"`
	Nonce  string              `json:"nonce"`
}

// RuntimeCapabilityTEERakAvrRequest is a worker RFC 0009 CapabilityTEE RAK AVR setup request message body.
type RuntimeCapabilityTEERakAvrRequest struct {
	AVR ias.AVRBundle `json:"avr"`
}

// RuntimeRPCCallRequest is a worker RPC call request message body.
type RuntimeRPCCallRequest struct {
	// Request.
	Request []byte `json:"request"`
}

// RuntimeRPCCallResponse is a worker RPC call response message body.
type RuntimeRPCCallResponse struct {
	// Response.
	Response []byte `json:"response"`
}

// RuntimeLocalRPCCallRequest is a worker local RPC call request message body.
type RuntimeLocalRPCCallRequest struct {
	// Request.
	Request []byte `json:"request"`
}

// RuntimeLocalRPCCallResponse is a worker local RPC call response message body.
type RuntimeLocalRPCCallResponse struct {
	// Response.
	Response []byte `json:"response"`
}

// RuntimeCheckTxBatchRequest is a worker check tx batch request message body.
type RuntimeCheckTxBatchRequest struct {
	// Batch of runtime inputs to check.
	Inputs transaction.RawBatch `json:"inputs"`
	// Block on which the batch check should be based.
	Block block.Block `json:"block"`
}

// RuntimeCheckTxBatchResponse is a worker check tx batch response message body.
type RuntimeCheckTxBatchResponse struct {
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
	// Messages are the emitted runtime messages.
	Messages []block.Message `json:"messages"`
}

// String returns a string representation of a computed batch.
func (b *ComputedBatch) String() string {
	return "<ComputedBatch>"
}

// RuntimeExecuteTxBatchRequest is a worker execute tx batch request message body.
type RuntimeExecuteTxBatchRequest struct {
	// MessageResults are the results of executing messages emitted by the
	// runtime in the previous round.
	MessageResults []*roothash.MessageEvent `json:"message_results,omitempty"`

	// IORoot is the I/O root containing the inputs (transactions) that
	// the compute node should use. It must match what is passed in "inputs".
	IORoot hash.Hash `json:"io_root"`
	// Batch of inputs (transactions).
	Inputs transaction.RawBatch `json:"inputs"`
	// Block on which the batch computation should be based.
	Block block.Block `json:"block"`
}

// RuntimeExecuteTxBatchResponse is a worker execute tx batch response message body.
type RuntimeExecuteTxBatchResponse struct {
	Batch ComputedBatch `json:"batch"`
}

// RuntimeKeyManagerPolicyUpdateRequest is a runtime key manager policy request
// message body.
type RuntimeKeyManagerPolicyUpdateRequest struct {
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
