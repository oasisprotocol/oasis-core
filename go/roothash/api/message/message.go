// Package message implements the supported runtime messages.
package message

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Message is a message that can be sent by a runtime.
type Message struct {
	Staking *StakingMessage `json:"staking,omitempty"`
}

// ValidateBasic performs basic validation of the runtime message.
func (m *Message) ValidateBasic() error {
	switch {
	case m.Staking != nil:
		return m.Staking.ValidateBasic()
	default:
		return fmt.Errorf("runtime message has no fields set")
	}
}

// MessagesHash returns a hash of provided runtime messages.
func MessagesHash(msgs []Message) (h hash.Hash) {
	if len(msgs) == 0 {
		// Special case if there are no messages.
		h.Empty()
		return
	}
	return hash.NewFrom(msgs)
}

// StakingMessage is a runtime message that allows a runtime to perform staking operations.
type StakingMessage struct {
	cbor.Versioned

	Transfer *staking.Transfer `json:"transfer,omitempty"`
	Withdraw *staking.Withdraw `json:"withdraw,omitempty"`
}

// ValidateBasic performs basic validation of the runtime message.
func (sm *StakingMessage) ValidateBasic() error {
	switch {
	case sm.Transfer != nil && sm.Withdraw != nil:
		return fmt.Errorf("staking runtime message has multiple fields set")
	case sm.Transfer != nil:
		// No validation at this time.
		return nil
	case sm.Withdraw != nil:
		// No validation at this time.
		return nil
	default:
		return fmt.Errorf("staking runtime message has no fields set")
	}
}
