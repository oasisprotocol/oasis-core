package message

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// IncomingMessage is an incoming message.
type IncomingMessage struct {
	// ID is the unique identifier of the message.
	ID uint64 `json:"id"`

	// Caller is the address of the caller authenticated by the consensus layer.
	Caller staking.Address `json:"caller"`

	// Tag is an optional tag provided by the caller which is ignored and can be used to match
	// processed incoming message events later.
	Tag uint64 `json:"tag,omitempty"`

	// Fee is the fee sent into the runtime as part of the message being sent. The fee is
	// transferred before the message is processed by the runtime.
	Fee quantity.Quantity `json:"fee,omitempty"`

	// Tokens are any tokens sent into the runtime as part of the message being sent. The tokens are
	// transferred before the message is processed by the runtime.
	Tokens quantity.Quantity `json:"tokens,omitempty"`

	// Data is arbitrary runtime-dependent data.
	Data []byte `json:"data,omitempty"`
}

// InMessagesHash returns a hash of provided incoming runtime messages.
func InMessagesHash(msgs []*IncomingMessage) (h hash.Hash) {
	if len(msgs) == 0 {
		// Special case if there are no messages.
		h.Empty()
		return
	}
	return hash.NewFrom(msgs)
}

// IncomingMessageQueueMeta is the incoming message queue metadata.
type IncomingMessageQueueMeta struct {
	// Size contains the current size of the queue.
	Size uint32 `json:"size,omitempty"`

	// NextSequenceNumber contains the sequence number that should be used for the next queued
	// message.
	NextSequenceNumber uint64 `json:"next_sequence_number,omitempty"`
}
