package api

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
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
	rules := CommissionScheduleRules{
		RateChangeInterval: 10,
		RateBoundLead:      30,
		MaxRateSteps:       4,
		MaxBoundSteps:      12,
	}

	cs := CommissionSchedule{
		Rates:  nil,
		Bounds: nil,
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "empty")
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
	}, &rules, 0), "amend init")

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
	}, &rules, 0), "amend init unsimultaneous")

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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "valid")

	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 11,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: nil,
	}, &rules, 10), "amend unaligned")

	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: nil,
	}, &rules, 10), "amend rate start too early")

	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: nil,
		Bounds: []CommissionRateBoundStep{
			{
				Start:   40,
				RateMin: mustInitQuantity(t, 10_000),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}, &rules, 10), "amend bound start too early")

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
	}, &rules, 10), "amend append")

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
	}, &rules, 10), "amend replace")

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
	}, &rules, 10), "amend out of bound")

	cs = CommissionSchedule{
		Rates: make([]CommissionRateStep, 5),
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	for i := range cs.Rates {
		// 0 through 40, inclusive.
		cs.Rates[i].Start = beacon.EpochTime(i * 10)
		cs.Rates[i].Rate = mustInitQuantity(t, int64(50_000+i))
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "overlong rate schedule")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: make([]CommissionRateBoundStep, 13),
	}
	for i := range cs.Bounds {
		// 0 through 40, inclusive.
		cs.Bounds[i].Start = beacon.EpochTime(i * 10)
		cs.Bounds[i].RateMin = mustInitQuantity(t, 0)
		cs.Bounds[i].RateMax = mustInitQuantity(t, int64(100_000-i))
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "overlong bound schedule")

	cs = CommissionSchedule{
		Rates: make([]CommissionRateStep, 4),
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	for i := range cs.Rates {
		// 0 through 30, inclusive.
		cs.Rates[i].Start = beacon.EpochTime(i * 10)
		cs.Rates[i].Rate = mustInitQuantity(t, int64(50_000+i))
	}
	amendment := CommissionSchedule{
		Rates:  make([]CommissionRateStep, 5),
		Bounds: nil,
	}
	for i := range amendment.Rates {
		// 40 through 80, inclusive.
		amendment.Rates[i].Start = beacon.EpochTime(40 + i*10)
		amendment.Rates[i].Rate = mustInitQuantity(t, int64(60_000+i))
	}
	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&amendment, &rules, 0), "overlong amendment rate schedule")

	cs = CommissionSchedule{
		Rates: make([]CommissionRateStep, 4),
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	for i := range cs.Rates {
		// 0 through 30, inclusive.
		cs.Rates[i].Start = beacon.EpochTime(i * 10)
		cs.Rates[i].Rate = mustInitQuantity(t, int64(50_000+i))
	}
	requireErrorShowDiagnostic(t, cs.AmendAndPruneAndValidate(&CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 40,
				Rate:  mustInitQuantity(t, 60_000),
			},
		},
		Bounds: nil,
	}, &rules, 0), "overlong rate schedule after amendment")

	cs = CommissionSchedule{
		Rates: make([]CommissionRateStep, 4),
		Bounds: []CommissionRateBoundStep{
			{
				Start:   0,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 100_000),
			},
		},
	}
	for i := range cs.Rates {
		// 0 through 30, inclusive.
		cs.Rates[i].Start = beacon.EpochTime(i * 10)
		cs.Rates[i].Rate = mustInitQuantity(t, int64(50_000+i))
	}
	amendment = CommissionSchedule{
		Rates:  make([]CommissionRateStep, 3),
		Bounds: nil,
	}
	for i := range amendment.Rates {
		// 30 through 60, inclusive.
		amendment.Rates[i].Start = beacon.EpochTime(30 + i*10)
		amendment.Rates[i].Rate = mustInitQuantity(t, int64(60_000+i))
	}
	require.NoError(t, cs.AmendAndPruneAndValidate(&amendment, &rules, 25), "complexity acceptable after replacing and pruning")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "unaligned rate step")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "reversed rate steps")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "zero-duration rate step")

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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "rate unity")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "rate over unity")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "unaligned bound step")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "reversed bound steps")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "bound min over unity")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "bound max over unity")

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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "bound exact")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "bound inverted")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "no rates")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "rates late start")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
		},
		Bounds: nil,
	}
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "no bounds")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "bounds late start")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "rate below min")

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
	requireErrorShowDiagnostic(t, cs.PruneAndValidateForGenesis(&rules, 0), "rate above max")

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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "bound change then rate change")

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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "rate change then bound change")

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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "simultaneous rate and bound change")

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
			{
				Start:   10,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 90_000),
			},
			{
				Start:   20,
				RateMin: mustInitQuantity(t, 0),
				RateMax: mustInitQuantity(t, 80_000),
			},
		},
	}
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "valid where len(rates) < len(bounds)")

	cs = CommissionSchedule{
		Rates: []CommissionRateStep{
			{
				Start: 0,
				Rate:  mustInitQuantity(t, 50_000),
			},
			{
				Start: 10,
				Rate:  mustInitQuantity(t, 60_000),
			},
			{
				Start: 20,
				Rate:  mustInitQuantity(t, 70_000),
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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 0), "valid where len(bounds) < len(rates)")

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
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 1), "prune no effect")
	require.Equal(t, beacon.EpochTime(0), cs.Rates[0].Start, "prune 1 rates start")
	require.Equal(t, beacon.EpochTime(0), cs.Bounds[0].Start, "prune 1 bounds start")
	require.NoError(t, cs.PruneAndValidateForGenesis(&rules, 10), "prune rate step")
	require.Equal(t, beacon.EpochTime(10), cs.Rates[0].Start, "prune 10 rates start")
	require.Equal(t, beacon.EpochTime(10), cs.Bounds[0].Start, "prune 10 bounds start")
}

func TestPrettyPrintCommissionRateStep(t *testing.T) {
	require := require.New(t)

	for _, t := range []struct {
		expectedPPrint string
		rateStart      beacon.EpochTime
		rateNumerator  *quantity.Quantity
		index          int
	}{
		{
			"" +
				"(1) start: epoch 10\n" +
				"    rate:  0.0%\n",
			beacon.EpochTime(10), quantity.NewFromUint64(0), 0,
		},
		{
			"" +
				"(11) start: epoch 20\n" +
				"     rate:  50.0%\n",
			beacon.EpochTime(20), quantity.NewFromUint64(50_000), 10,
		},
		{
			"" +
				"(101) start: epoch 100\n" +
				"      rate:  100.0%\n",
			beacon.EpochTime(100), quantity.NewFromUint64(100_000), 100,
		},
	} {
		rateStep := CommissionRateStep{
			Start: t.rateStart,
			Rate:  *t.rateNumerator,
		}
		var b bytes.Buffer
		ctx := context.WithValue(context.Background(), prettyprint.ContextKeyCommissionScheduleIndex, t.index)
		rateStep.PrettyPrint(ctx, "", &b)
		pPrint := b.String()
		require.Equal(t.expectedPPrint, pPrint, "obtained pretty print didn't match expected value")
	}
}

func TestPrettyPrintCommissionRateBoundStep(t *testing.T) {
	require := require.New(t)

	for _, t := range []struct {
		expectedPPrint   string
		rateStart        beacon.EpochTime
		rateMinNumerator *quantity.Quantity
		rateMaxNumerator *quantity.Quantity
		index            int
	}{
		{
			"" +
				"(1) start:        epoch 10\n" +
				"    minimum rate: 0.0%\n" +
				"    maximum rate: 20.0%\n",
			beacon.EpochTime(10), quantity.NewFromUint64(0), quantity.NewFromUint64(20_000), 0,
		},
		{
			"" +
				"(11) start:        epoch 20\n" +
				"     minimum rate: 40.0%\n" +
				"     maximum rate: 60.0%\n",
			beacon.EpochTime(20), quantity.NewFromUint64(40_000), quantity.NewFromUint64(60_000), 10,
		},
		{
			"" +
				"(101) start:        epoch 100\n" +
				"      minimum rate: 0.0%\n" +
				"      maximum rate: 100.0%\n",
			beacon.EpochTime(100), quantity.NewFromUint64(0), quantity.NewFromUint64(100_000), 100,
		},
	} {
		rateStep := CommissionRateBoundStep{
			Start:   t.rateStart,
			RateMin: *t.rateMinNumerator,
			RateMax: *t.rateMaxNumerator,
		}
		var b bytes.Buffer
		ctx := context.WithValue(context.Background(), prettyprint.ContextKeyCommissionScheduleIndex, t.index)
		rateStep.PrettyPrint(ctx, "", &b)
		pPrint := b.String()
		require.Equal(t.expectedPPrint, pPrint, "obtained pretty print didn't match expected value")
	}
}
