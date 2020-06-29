package api

import (
	"math/big"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

// RewardAmountDenominator is the denominator for the reward rate.
var RewardAmountDenominator *quantity.Quantity

// RewardStep is one of the time periods in the reward schedule.
type RewardStep struct {
	Until epochtime.EpochTime `json:"until"`
	Scale quantity.Quantity   `json:"scale"`
}

func init() {
	// Denominated in one millionth of a percent.
	RewardAmountDenominator = quantity.NewQuantity()
	err := RewardAmountDenominator.FromBigInt(big.NewInt(100_000_000))
	if err != nil {
		panic(err)
	}
}
