// Package message implements the supported runtime messages.
package message

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Message is a message that can be sent by a runtime.
type Message struct {
	Staking  *StakingMessage  `json:"staking,omitempty"`
	Registry *RegistryMessage `json:"registry,omitempty"`
}

// ValidateBasic performs basic validation of the runtime message.
func (m *Message) ValidateBasic() error {
	switch {
	case m.Staking != nil:
		return m.Staking.ValidateBasic()
	case m.Registry != nil:
		return m.Registry.ValidateBasic()
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

	Transfer      *staking.Transfer      `json:"transfer,omitempty"`
	Withdraw      *staking.Withdraw      `json:"withdraw,omitempty"`
	AddEscrow     *staking.Escrow        `json:"add_escrow,omitempty"`
	ReclaimEscrow *staking.ReclaimEscrow `json:"reclaim_escrow,omitempty"`
}

// ValidateBasic performs basic validation of the runtime message.
func (sm *StakingMessage) ValidateBasic() error {
	var setFields uint8
	if sm.Transfer != nil {
		// No validation at this time.
		setFields++
	}
	if sm.Withdraw != nil {
		// No validation at this time.
		setFields++
	}
	if sm.AddEscrow != nil {
		// No validation at this time.
		setFields++
	}
	if sm.ReclaimEscrow != nil {
		// No validation at this time.
		setFields++
	}
	switch setFields {
	case 0:
		return fmt.Errorf("staking runtime message has no fields set")
	case 1:
		// Ok.
		return nil
	default:
		return fmt.Errorf("staking runtime message has multiple fields set")
	}
}

// RegistryMessage is a runtime message that allows a runtime to perform staking operations.
type RegistryMessage struct {
	cbor.Versioned

	UpdateRuntime *registry.Runtime `json:"update_runtime,omitempty"`
}

// ValidateBasic performs basic validation of the runtime message.
func (rm *RegistryMessage) ValidateBasic() error {
	switch {
	case rm.UpdateRuntime != nil:
		// The runtime descriptor will already be validated in registerRuntime
		// in the registry app when it processes the message, so we don't have
		// to do any validation here.
		return nil
	default:
		return fmt.Errorf("registry runtime message has no fields set")
	}
}
