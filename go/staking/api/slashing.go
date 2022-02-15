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
	// SlashConsensusLightClientAttack is slashing due to light client attacks.
	SlashConsensusLightClientAttack SlashReason = 0x04

	// SlashRuntimeIncorrectResults is slashing due to submission of incorrect
	// results in runtime executor commitments.
	SlashRuntimeIncorrectResults SlashReason = 0x80
	// SlashRuntimeEquivocation is slashing due to signing two different
	// executor commits or proposed batches for the same round.
	SlashRuntimeEquivocation SlashReason = 0x81
	// SlashRuntimeLiveness is slashing due to not doing the required work.
	SlashRuntimeLiveness SlashReason = 0x82

	// SlashConsensusEquivocationName is the string representation of SlashConsensusEquivocation.
	SlashConsensusEquivocationName = "consensus-equivocation"
	// SlashConsensusLightClientAttackName is the string representation of SlashConsensusLightClientAttack.
	SlashConsensusLightClientAttackName = "consensus-light-client-attack"
	// SlashRuntimeIncorrectResultsName is the string representation of SlashRuntimeIncorrectResultsName.
	SlashRuntimeIncorrectResultsName = "runtime-incorrect-results"
	// SlashRuntimeEquivocationName is the string representation of SlashRuntimeEquivocation.
	SlashRuntimeEquivocationName = "runtime-equivocation"
	// SlashRuntimeLivenessName is the string representation of SlashRuntimeLiveness.
	SlashRuntimeLivenessName = "runtime-liveness"
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
	case SlashConsensusLightClientAttack:
		return SlashConsensusLightClientAttackName, nil
	case SlashRuntimeIncorrectResults:
		return SlashRuntimeIncorrectResultsName, nil
	case SlashRuntimeEquivocation:
		return SlashRuntimeEquivocationName, nil
	case SlashRuntimeLiveness:
		return SlashRuntimeLivenessName, nil
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
	case SlashConsensusEquivocationName:
		*s = SlashConsensusEquivocation
	case SlashConsensusLightClientAttackName:
		*s = SlashConsensusLightClientAttack
	case SlashRuntimeIncorrectResultsName:
		*s = SlashRuntimeIncorrectResults
	case SlashRuntimeEquivocationName:
		*s = SlashRuntimeEquivocation
	case SlashRuntimeLivenessName:
		*s = SlashRuntimeLiveness
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
