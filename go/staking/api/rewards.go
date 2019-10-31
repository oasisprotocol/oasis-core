package api

import (
	"math/big"
)

var RewardAmountDenominator *Quantity

func init() {
	// Denominated in 1000th of a percent.
	RewardAmountDenominator = NewQuantity()
	err := RewardAmountDenominator.FromBigInt(big.NewInt(100_000))
	if err != nil {
		panic(err)
	}
}
