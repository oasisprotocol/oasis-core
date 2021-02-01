package api

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

// SlashReason is the reason why a node was slashed.
type SlashReason uint8

const (
	// SlashConsensusEquivocation is slashing due to equivocation.
	SlashConsensusEquivocation SlashReason = 0x00
	// SlashBeaconInvalidCommit is slashing due to invalid commit behavior.
	SlashBeaconInvalidCommit SlashReason = 0x01
	// SlashBeaconInvalidReveal is slashing due to invalid reveal behavior.
	SlashBeaconInvalidReveal SlashReason = 0x02
	// SlashBeaconNonparticipation is slashing due to nonparticipation.
	SlashBeaconNonparticipation SlashReason = 0x03

	// SlashConsensusEquivocationName is the string representation of SlashConsensusEquivocation.
	SlashConsensusEquivocationName = "consensus-equivocation"
	// SlashBeaconInvalidCommitName is the string representation of SlashBeaconInvalidCommit.
	SlashBeaconInvalidCommitName = "beacon-invalid-commit"
	// SlashBeaconInvalidRevealName is the string representation of SlashBeaconInvalidReveal.
	SlashBeaconInvalidRevealName = "beacon-invalid-reveal"
	// SlashBeaconNonparticipationName is the string representation of SlashBeaconNonparticipation.
	SlashBeaconNonparticipationName = "beacon-nonparticipation"
)

// String returns a string representation of a SlashReason.
func (s SlashReason) String() string {
	str, _ := s.checkedString()
	return str
}

func (s SlashReason) checkedString() (string, error) {
	switch s {
	case SlashConsensusEquivocation:
		return SlashConsensusEquivocationName, nil
	case SlashBeaconInvalidCommit:
		return SlashBeaconInvalidCommitName, nil
	case SlashBeaconInvalidReveal:
		return SlashBeaconInvalidRevealName, nil
	case SlashBeaconNonparticipation:
		return SlashBeaconNonparticipationName, nil
	default:
		return "[unknown slash reason]", fmt.Errorf("unknown slash reason: %d", s)
	}
}

// MarshalText encodes a SlashReason into text form.
func (s SlashReason) MarshalText() ([]byte, error) {
	str, err := s.checkedString()
	if err != nil {
		return nil, err
	}

	return []byte(str), nil
}

// UnmarshalText decodes a text slice into a SlashReason.
func (s *SlashReason) UnmarshalText(text []byte) error {
	switch string(text) {
	// XXX: The "0" case is only for backward compatibility, so that the old
	// genesis file loads -- remove this once mainnet is upgraded!
	case "0":
		fallthrough
	case SlashConsensusEquivocationName:
		*s = SlashConsensusEquivocation
	case SlashBeaconInvalidCommitName:
		*s = SlashBeaconInvalidCommit
	case SlashBeaconInvalidRevealName:
		*s = SlashBeaconInvalidReveal
	case SlashBeaconNonparticipationName:
		*s = SlashBeaconNonparticipation
	default:
		return fmt.Errorf("invalid slash reason: %s", string(text))
	}
	return nil
}

// Slash is the per-reason slashing configuration.
type Slash struct {
	Amount         quantity.Quantity `json:"amount"`
	FreezeInterval beacon.EpochTime  `json:"freeze_interval"`
}
