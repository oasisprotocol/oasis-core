package api

import (
	"github.com/oasislabs/oasis-core/go/common/quantity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

// CommissionRateDenominator is the denominator for the commission rate.
var CommissionRateDenominator *quantity.Quantity

type CommissionRateStep struct {
	Start epochtime.EpochTime `json:"start"`
	Rate  quantity.Quantity   `json:"rate"`
}

type CommissionRateBoundStep struct {
	Start   epochtime.EpochTime `json:"start"`
	RateMin quantity.Quantity   `json:"rate_min"`
	RateMax quantity.Quantity   `json:"rate_max"`
}

type CommissionSchedule struct {
	Rates  []CommissionRateStep      `json:"rates"`
	Bounds []CommissionRateBoundStep `json:"bounds"`
}

func init() {
	// Denominated in 1000th of a percent.
	CommissionRateDenominator = quantity.NewQuantity()
	err := CommissionRateDenominator.FromInt64(100_000)
	if err != nil {
		panic(err)
	}
}
