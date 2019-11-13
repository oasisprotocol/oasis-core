package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/quantity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

func mustInitQuantity(t *testing.T, i int64) (q quantity.Quantity) {
	require.NoError(t, q.FromInt64(i), "FromInt64")
	return
}

func mustInitQuantityP(t *testing.T, i int64) *quantity.Quantity {
	q := mustInitQuantity(t, i)
	return &q
}

func requireErrorShowDiagnostic(t *testing.T, err error, msg string) {
	require.Error(t, err, msg)
	t.Log(msg+":", err)
}

func TestCommissionSchedule(t *testing.T) {
	cs := CommissionSchedule{
		Rates:  nil,
		Bounds: nil,
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(0, 10), "empty")
	require.Nil(t, cs.CurrentRate(0), "empty current rate")
	require.NoError(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 40,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   40,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}, 0, 10, 30), "amend init")

	cs = CommissionSchedule{
		Rates:  nil,
		Bounds: nil,
	}
	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   40,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}, 0, 10, 30), "amend init unsimultaneous")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(0, 10), "valid")

	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 11,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: nil,
	}, 10, 10, 30), "amend unaligned")

	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: nil,
	}, 10, 10, 30), "amend rate start too early")

	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: nil,
		Bounds: []CommissionRateBoundStep{
			{
				Start:   40,
				RateMin: mustInitQuantity(t, 10_000),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}, 10, 10, 30), "amend bound start too early")

	require.NoError(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 20,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   50,
				RateMin: mustInitQuantity(t, 10_000),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}, 10, 10, 30), "amend append")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
			{
				Start: 50,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
			{
				Start:   50,
				RateMin: mustInitQuantity(t, 10_000),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	require.Equal(t, mustInitQuantityP(t, 50_000), cs.CurrentRate(0), "current rate 0")
	require.Equal(t, mustInitQuantityP(t, 50_000), cs.CurrentRate(1), "current rate 1")
	require.Equal(t, mustInitQuantityP(t, 60_000), cs.CurrentRate(50), "current rate 1")
	require.Equal(t, mustInitQuantityP(t, 60_000), cs.CurrentRate(999), "current rate 999")
	require.NoError(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 20,
				Rate:  mustInitQuantity(t, 70_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   50,
				RateMin: mustInitQuantity(t, 20_000),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}, 10, 10, 30), "amend replace")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 50_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 20,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: nil,
	}, 10, 10, 30), "amend out of bound")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 1,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "unaligned rate step")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 50_000),
			},
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "reversed rate steps")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "zero-duration rate step")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 100_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(0, 10), "rate unity")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 110_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "rate over unity")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   1,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "unaligned bound step")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   10,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 90_000),
			},
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "reversed bound steps")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 100_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 110_000),
				RateMax: mustInitQuantity(t, 120_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "bound min over unity")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 110_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "bound max over unity")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 50_000),
				RateMax: mustInitQuantity(t, 50_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(0, 10), "bound exact")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 60_000),
				RateMax: mustInitQuantity(t, 40_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "bound inverted")

	cs = CommissionSchedule{
		Rates: nil,
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "no rates")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "rates late start")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: nil,
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "no bounds")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   10,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "bounds late start")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 30_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 40_000),
				RateMax: mustInitQuantity(t, 60_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "rate below min")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 70_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 40_000),
				RateMax: mustInitQuantity(t, 60_000),
			},
		},
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(0, 10), "rate above max")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
			{
				Start: 20,
				Rate:  mustInitQuantity(t, 45_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
			{
				Start:   10,
				RateMin: mustInitQuantity(t, 40_000),
				RateMax: mustInitQuantity(t, 60_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(0, 10), "bound change then rate change")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 45_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
			{
				Start:   20,
				RateMin: mustInitQuantity(t, 40_000),
				RateMax: mustInitQuantity(t, 60_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(0, 10), "rate change then bound change")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 10_000),
			},
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 40_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 20_000),
			},
			{
				Start:   10,
				RateMin: mustInitQuantity(t, 30_000),
				RateMax: mustInitQuantity(t, 50_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(0, 10), "simultaneous rate and bound change")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 10_000),
			},
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 20_000),
			},
		},
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
			{
				Start:   10,
				RateMin: mustInitQuantity(t, 10_000),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(1, 10), "prune no effect")
	require.Equal(t, epochtime.EpochTime(0), cs.Rates[0].Start, "prune 1 rates start")
	require.Equal(t, epochtime.EpochTime(0), cs.Bounds[0].Start, "prune 1 bounds start")
	require.NoError(t, cs.PruneAndValidateForGenesis(10, 10), "prune rate step")
	require.Equal(t, epochtime.EpochTime(10), cs.Rates[0].Start, "prune 10 rates start")
	require.Equal(t, epochtime.EpochTime(10), cs.Bounds[0].Start, "prune 10 bounds start")
}
