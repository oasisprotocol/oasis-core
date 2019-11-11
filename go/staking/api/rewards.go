package api

import (
	"math/big"

	"github.com/oasislabs/oasis-core/go/common/quantity"
)

// RewardAmountDenominator is the denominator for the reward rate.
var RewardAmountDenominator *quantity.Quantity

func init() {
	// Denominated in 1000th of a percent.
	RewardAmountDenominator = quantity.NewQuantity()
	err := RewardAmountDenominator.FromBigInt(big.NewInt(100_000))
	if err != nil {
		panic(err)
	}
}
