package api

import (
	"math/big"
)

// RewardAmountDenominator is the denominator for the reward rate.
var RewardAmountDenominator *Quantity

func init() {
	// Denominated in 1000th of a percent.
	RewardAmountDenominator = NewQuantity()
	err := RewardAmountDenominator.FromBigInt(big.NewInt(100_000))
	if err != nil {
		panic(err)
	}
}
