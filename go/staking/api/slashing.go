package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

// SlashReason is the reason why a node was slashed.
type SlashReason int

const (
	// SlashDoubleSigning is slashing due to double signing.
	SlashDoubleSigning SlashReason = 0

	SlashMax = SlashDoubleSigning
)

// String returns a string representation of a SlashReason.
func (s SlashReason) String() string {
	switch s {
	case SlashDoubleSigning:
		return "double-signing"
	default:
		return "[unknown slash reason]"
	}
}

// Slash is the per-reason slashing configuration.
type Slash struct {
	Amount         quantity.Quantity   `json:"amount"`
	FreezeInterval epochtime.EpochTime `json:"freeze_interval"`
}
