package api

import (
	"math/big"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

// RewardAmountDenominator is the denominator for the reward rate.
var RewardAmountDenominator *quantity.Quantity

// RewardStep is one of the time periods in the reward schedule.
type RewardStep struct {
	Until beacon.EpochTime  `json:"until"`
	Scale quantity.Quantity `json:"scale"`
}

func init() {
	// Denominated in one millionth of a percent.
	RewardAmountDenominator = quantity.NewQuantity()
	err := RewardAmountDenominator.FromBigInt(big.NewInt(100_000_000))
	if err != nil {
		panic(err)
	}
}
