package p2p

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/runtime"
	roothash "github.com/oasislabs/ekiden/go/roothash/api/block"
)

// Message is a message sent to nodes in the same computation group.
type Message struct {
	// RuntimeID is the identifier of the runtime this message
	// belongs to. It is used as a namespace.
	RuntimeID signature.PublicKey

	// GroupHash is the hash identifying the group this message
	// is from/to. Messages with non-matching group hashes will
	// be discarded.
	GroupHash hash.Hash

	// Jaeger's span context in binary format.
	SpanContext []byte

	Ack   *Ack
	Error *Error

	// Batch dispatch.
	LeaderBatchDispatch *LeaderBatchDispatch
}

type LeaderBatchDispatch struct {
	// Batch is the dispatched transaction batch.
	Batch runtime.Batch

	// Header is the block header on which the batch should be
	// based.
	Header roothash.Header
}

// Ack is an acknowledgement that a message was received.
type Ack struct {
}

// Error is an error response.
type Error struct {
	// Message is an error message.
	Message string
}
