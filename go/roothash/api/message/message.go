// Package message implements the supported runtime messages.
package message

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Message is a message that can be sent by a runtime.
type Message struct {
	Staking    *StakingMessage    `json:"staking,omitempty"`
	Registry   *RegistryMessage   `json:"registry,omitempty"`
	Governance *GovernanceMessage `json:"governance,omitempty"`
}

// ValidateBasic performs basic validation of the runtime message.
func (m *Message) ValidateBasic() error {
	switch {
	case m.Staking != nil:
		return m.Staking.ValidateBasic()
	case m.Registry != nil:
		return m.Registry.ValidateBasic()
	case m.Governance != nil:
		return m.Governance.ValidateBasic()
	default:
		return fmt.Errorf("runtime message has no fields set")
	}
}

// MessagesHash returns a hash of provided runtime messages.
func MessagesHash(msgs []Message) hash.Hash {
	if len(msgs) == 0 {
		// Special case if there are no messages.
		var h hash.Hash
		h.Empty()
		return h
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

// GovernanceMessage is a governance message that allows a runtime to perform governance operations.
type GovernanceMessage struct {
	cbor.Versioned

	CastVote       *governance.ProposalVote    `json:"cast_vote,omitempty"`
	SubmitProposal *governance.ProposalContent `json:"submit_proposal,omitempty"`
}

// ValidateBasic performs basic validation of a governance message.
func (gm *GovernanceMessage) ValidateBasic() error {
	switch {
	case gm.CastVote != nil && gm.SubmitProposal != nil:
		return fmt.Errorf("governance runtime message has multiple fields set")
	case gm.SubmitProposal != nil:
		// No extra validation validation at this time.
		return nil
	case gm.CastVote != nil:
		// No extra validation validation at this time.
		return nil
	default:
		return fmt.Errorf("governance runtime message has no fields set")
	}
}
