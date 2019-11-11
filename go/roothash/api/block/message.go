package block

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
)

// AdjustmentOp is the Op in StakingGeneralAdjustmentRoothashMessage
type AdjustmentOp uint8

const (
	// Increase adds the amount to the general balance.
	Increase AdjustmentOp = 1

	// Decrease subtracts the amount from the general balance.
	Decrease AdjustmentOp = 2
)

// StakingGeneralAdjustmentRoothashMessage is a message that changes an account's general balance.
// Mux app in charge: staking
type StakingGeneralAdjustmentRoothashMessage struct {
	Account signature.PublicKey `json:"account"`
	Op      AdjustmentOp        `json:"op"`
	Amount  *quantity.Quantity  `json:"amount"`
}

// RoothashMessage is a roothash message.
type RoothashMessage struct {
	StakingGeneralAdjustmentRoothashMessage *StakingGeneralAdjustmentRoothashMessage
}
