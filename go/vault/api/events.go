package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Event signifies a vault event.
type Event struct {
	Height int64     `json:"height,omitempty"`
	TxHash hash.Hash `json:"tx_hash,omitempty"`

	ActionSubmitted  *ActionSubmittedEvent  `json:"action_submitted,omitempty"`
	ActionCanceled   *ActionCanceledEvent   `json:"action_canceled,omitempty"`
	ActionExecuted   *ActionExecutedEvent   `json:"action_executed,omitempty"`
	StateChanged     *StateChangedEvent     `json:"state_changed,omitempty"`
	PolicyUpdated    *PolicyUpdatedEvent    `json:"policy_updated"`
	AuthorityUpdated *AuthorityUpdatedEvent `json:"authority_updated"`
}

// ActionSubmittedEvent is the event emitted when a new vault action is submitted.
type ActionSubmittedEvent struct {
	// Submitter is the account address of the submitter.
	Submitter staking.Address `json:"submitter"`
	// Vault is the vault address.
	Vault staking.Address `json:"vault"`
	// Nonce is the action nonce.
	Nonce uint64 `json:"nonce"`
}

// EventKind returns a string representation of this event's kind.
func (e *ActionSubmittedEvent) EventKind() string {
	return "action_submitted"
}

// ActionCanceledEvent is the event emitted when a vault action is canceled.
type ActionCanceledEvent struct {
	// Vault is the vault address.
	Vault staking.Address `json:"vault"`
	// Nonce is the action nonce.
	Nonce uint64 `json:"nonce"`
}

// EventKind returns a string representation of this event's kind.
func (e *ActionCanceledEvent) EventKind() string {
	return "action_canceled"
}

// ActionExecutedEvent is the event emitted when a new vault action is executed.
type ActionExecutedEvent struct {
	// Vault is the vault address.
	Vault staking.Address `json:"vault"`
	// Nonce is the action nonce.
	Nonce uint64 `json:"nonce"`
	// Result is the action execution result.
	Result ActionExecutionResult `json:"result,omitempty"`
}

// EventKind returns a string representation of this event's kind.
func (e *ActionExecutedEvent) EventKind() string {
	return "action_executed"
}

// ActionExecutionResult is the result of executing an action.
type ActionExecutionResult struct {
	Module string `json:"module,omitempty"`
	Code   uint32 `json:"code,omitempty"`
}

// StateChangedEvent is the event emitted when a vault state is changed.
type StateChangedEvent struct {
	// Vault is the vault address.
	Vault staking.Address `json:"vault"`
	// OldState is the old vault state.
	OldState State `json:"old_state"`
	// NewState is the new vault state.
	NewState State `json:"new_state"`
}

// EventKind returns a string representation of this event's kind.
func (e *StateChangedEvent) EventKind() string {
	return "state_changed"
}

// PolicyUpdatedEvent is the event emitted when a vault policy for an address is updated.
type PolicyUpdatedEvent struct {
	// Vault is the vault address.
	Vault staking.Address `json:"vault"`
	// Address is the address for which the policy has been updated.
	Address staking.Address `json:"address"`
}

// EventKind returns a string representation of this event's kind.
func (e *PolicyUpdatedEvent) EventKind() string {
	return "policy_updated"
}

// AuthorityUpdatedEvent is the event emitted when a vault authority is updated.
type AuthorityUpdatedEvent struct {
	// Vault is the vault address.
	Vault staking.Address `json:"vault"`
}

// EventKind returns a string representation of this event's kind.
func (e *AuthorityUpdatedEvent) EventKind() string {
	return "authority_updated"
}
