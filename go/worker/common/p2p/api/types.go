package api

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

// NOTE: Bump CommitteeProtocol version in go/common/version if you
//       change any of the structures below.

// CommitteeMessage is a message published to nodes via gossipsub on the committee topic.
type CommitteeMessage struct {
	// Epoch is the epoch this message belongs to.
	Epoch beacon.EpochTime `json:"epoch,omitempty"`

	// Proposal is a batch proposal.
	Proposal *commitment.Proposal `json:",omitempty"`
}

// TxMessage is a message published to nodes via gossipsub on the transaction topic. It contains the
// raw signed transaction with runtime-dependent semantics.
type TxMessage []byte
