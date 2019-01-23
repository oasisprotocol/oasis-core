package protocol

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/ias"
	"github.com/oasislabs/ekiden/go/common/runtime"
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
	case MessageKeepAlive:
		return "keep-alive"
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

	// KeepAlive message.
	MessageKeepAlive MessageType = 3
)

// Message is a protocol message.
type Message struct {
	ID          uint64      `codec:"id"`
	MessageType MessageType `codec:"message_type"`
	Body        Body        `codec:"body"`
}

// Body is a protocol message body.
type Body struct {
	_struct struct{} `codec:",omitempty"` // nolint

	Empty *Empty
	Error *Error

	// Worker interface.
	WorkerPingRequest                   *Empty
	WorkerShutdownRequest               *Empty
	WorkerCapabilityTEEGidRequest       *Empty
	WorkerCapabilityTEEGidResponse      *WorkerCapabilityTEEGidResponse
	WorkerCapabilityTEERakQuoteRequest  *WorkerCapabilityTEERakQuoteRequest
	WorkerCapabilityTEERakQuoteResponse *WorkerCapabilityTEERakQuoteResponse
	WorkerRPCCallRequest                *WorkerRPCCallRequest
	WorkerRPCCallResponse               *WorkerRPCCallResponse
	WorkerRuntimeCallBatchRequest       *WorkerRuntimeCallBatchRequest
	WorkerRuntimeCallBatchResponse      *WorkerRuntimeCallBatchResponse
	WorkerAbortRequest                  *Empty
	WorkerAbortResponse                 *Empty

	// Host interface.
	HostRPCCallRequest          *HostRPCCallRequest
	HostRPCCallResponse         *HostRPCCallResponse
	HostIasGetSpidRequest       *Empty
	HostIasGetSpidResponse      *HostIasGetSpidResponse
	HostIasGetQuoteTypeRequest  *Empty
	HostIasGetQuoteTypeResponse *HostIasGetQuoteTypeResponse
	HostIasSigRlRequest         *HostIasSigRlRequest
	HostIasSigRlResponse        *HostIasSigRlResponse
	HostIasReportRequest        *HostIasReportRequest
	HostIasReportResponse       *HostIasReportResponse
	HostStorageGetRequest       *HostStorageGetRequest
	HostStorageGetResponse      *HostStorageGetResponse
	HostStorageGetBatchRequest  *HostStorageGetBatchRequest
	HostStorageGetBatchResponse *HostStorageGetBatchResponse
}

// Empty is an empty message body.
type Empty struct {
}

// Error is a message body representing an error.
type Error struct {
	Message string `codec:"message"`
}

// WorkerCapabilityTEEGidResponse is a worker RFC 0009 CapabilityTEE EPID group ID response message body.
type WorkerCapabilityTEEGidResponse struct {
	Gid [4]byte `codec:"gid"`
}

// WorkerCapabilityTEERakQuoteRequest is a worker RFC 0009 CapabilityTEE RAK request message body.
type WorkerCapabilityTEERakQuoteRequest struct {
	QuoteType uint32   `codec:"quote_type"`
	SPID      ias.SPID `codec:"spid"`
	SigRL     []byte   `codec:"sig_rl"`
}

// WorkerCapabilityTEERakQuoteResponse is a worker RFC 0009 CapabilityTEE RAK response message body.
type WorkerCapabilityTEERakQuoteResponse struct {
	RakPub signature.PublicKey `codec:"rak_pub"`
	Quote  []byte              `codec:"quote"`
}

// WorkerRPCCallRequest is a worker RPC call request message body.
type WorkerRPCCallRequest struct {
	Request []byte `codec:"request"`
}

// WorkerRPCCallResponse is a worker RPC call response message body.
type WorkerRPCCallResponse struct {
	Response []byte `codec:"response"`
}

// ComputedBatch is a computed batch.
type ComputedBatch struct {
	// Block this batch was computed against.
	Block roothash.Block `codec:"block"`
	// Batch of runtime calls.
	Calls runtime.Batch `codec:"calls"`
	// Batch of runtime outputs.
	Outputs runtime.Batch `codec:"outputs"`
	// Batch of storage inserts.
	StorageInserts []storage.Value `codec:"storage_inserts"`
	// New state root hash.
	NewStateRoot hash.Hash `codec:"new_state_root"`
}

// String returns a string representation of a computed batch.
func (b *ComputedBatch) String() string {
	return "<ComputedBatch>"
}

// WorkerRuntimeCallBatchRequest is a worker batch runtime call request message body.
type WorkerRuntimeCallBatchRequest struct {
	Calls runtime.Batch  `codec:"calls"`
	Block roothash.Block `codec:"block"`
}

// WorkerRuntimeCallBatchResponse is a worker batch runtime call response message body.
type WorkerRuntimeCallBatchResponse struct {
	Batch ComputedBatch `codec:"batch"`
}

// ClientEndpoint is a RPC client endpoint.
type ClientEndpoint uint16

const (
	// EndpointInvalid is an invalid client endpoint (should never be seen on the wire).
	EndpointInvalid ClientEndpoint = 0

	// EndpointKeyManager is a key manager client endpoint.
	EndpointKeyManager ClientEndpoint = 1
)

// HostRPCCallRequest is a host RPC call request message body.
type HostRPCCallRequest struct {
	Endpoint ClientEndpoint `codec:"endpoint"`
	Request  []byte         `codec:"request"`
}

// HostRPCCallResponse is a host RPC call response message body.
type HostRPCCallResponse struct {
	Response []byte `codec:"response"`
}

// HostIasGetSpidResponse is a host IAS get SPID response message body.
type HostIasGetSpidResponse struct {
	SPID ias.SPID `codec:"spid"`
}

// HostIasGetQuoteTypeResponse is a host IAS get quote type response message body.
type HostIasGetQuoteTypeResponse struct {
	QuoteType uint32 `codec:"quote_type"`
}

// HostIasSigRlRequest is a host IAS signature revocation list request message body.
type HostIasSigRlRequest struct {
	GID uint32 `codec:"gid"`
}

// HostIasSigRlResponse is a host IAS signature revocation list response message body.
type HostIasSigRlResponse struct {
	SigRL []byte `codec:"sigrl"`
}

// HostIasReportRequest is a host IAS report generation request message body.
type HostIasReportRequest struct {
	Quote []byte `codec:"quote"`
}

// HostIasReportResponse is a host IAS report generation response message body.
type HostIasReportResponse struct {
	AVR          []byte `codec:"avr"`
	Signature    []byte `codec:"signature"`
	Certificates []byte `codec:"certificates"`
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
