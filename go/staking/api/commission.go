package api

import (
	"fmt"

	"github.com/pkg/errors"

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

func (cs *CommissionSchedule) validateComplexity(commissionScheduleMaxRateSteps int, commissionScheduleMaxBoundSteps int) error {
	if len(cs.Rates) > commissionScheduleMaxRateSteps {
		return fmt.Errorf("rate schedule %d steps exceeds maximum %d", len(cs.Rates), commissionScheduleMaxRateSteps)
	}
	if len(cs.Bounds) > commissionScheduleMaxBoundSteps {
		return fmt.Errorf("bound schedule %d steps exceeds maximum %d", len(cs.Bounds), commissionScheduleMaxBoundSteps)
	}

	return nil
}

// validateNondegenerate detects degenerate steps.
func (cs *CommissionSchedule) validateNondegenerate(commissionRateChangeInterval epochtime.EpochTime) error {
	for i, step := range cs.Rates {
		if step.Start%commissionRateChangeInterval != 0 {
			return fmt.Errorf("rate step %d start epoch %d not aligned with commission rate change interval %d", i, step.Start, commissionRateChangeInterval)
		}
		if i > 0 && step.Start <= cs.Rates[i-1].Start {
			return fmt.Errorf("rate step %d start epoch %d not after previous step start epoch %d", i, step.Start, cs.Rates[i-1].Start)
		}
		if step.Rate.Cmp(CommissionRateDenominator) > 0 {
			return fmt.Errorf("rate step %d rate %v/%v over unity", i, step.Rate, CommissionRateDenominator)
		}
	}

	for i, step := range cs.Bounds {
		if step.Start%commissionRateChangeInterval != 0 {
			return fmt.Errorf("bound step %d start epoch %d not aligned with commission rate change interval %d", i, step.Start, commissionRateChangeInterval)
		}
		if i > 0 && step.Start <= cs.Rates[i-1].Start {
			return fmt.Errorf("bound step %d start epoch %d not after previous step start epoch %d", i, step.Start, cs.Rates[i-1].Start)
		}
		if step.RateMin.Cmp(CommissionRateDenominator) > 0 {
			return fmt.Errorf("bound step %d minimum rate %v/%v over unity", i, step.RateMin, CommissionRateDenominator)
		}
		if step.RateMax.Cmp(CommissionRateDenominator) > 0 {
			return fmt.Errorf("bound step %d maximum rate %v/%v over unity", i, step.RateMax, CommissionRateDenominator)
		}
		if step.RateMax.Cmp(&step.RateMin) < 0 {
			return fmt.Errorf("bound step %d maximum rate %v/%v less than minimum rate %v/%v", i, step.RateMax, CommissionRateDenominator, step.RateMin, CommissionRateDenominator)
		}
	}

	return nil
}

// validateAmendmentAcceptable apply policy for "when" changes can be made, for CommissionSchedules that are amendments.
func (cs *CommissionSchedule) validateAmendmentAcceptable(now epochtime.EpochTime, commissionRateBoundLead epochtime.EpochTime) error {
	if len(cs.Rates) != 0 {
		if cs.Rates[0].Start <= now {
			return fmt.Errorf("rate schedule with start epoch %d must not alter rate on or before %d", cs.Rates[0].Start, now)
		}
	}

	if len(cs.Bounds) != 0 {
		if cs.Bounds[0].Start <= now+commissionRateBoundLead {
			return fmt.Errorf("bound schedule with start epoch %d must not alter bound on or before %d", cs.Bounds[0].Start, now+commissionRateBoundLead)
		}
	}

	return nil
}

// prune discards past steps that aren't in effect anymore.
func (cs *CommissionSchedule) prune(now epochtime.EpochTime) {
	for len(cs.Rates) > 1 {
		if cs.Rates[1].Start > now {
			// Remaining steps haven't started yet, so keep them and the current active one.
			break
		}

		cs.Rates = cs.Rates[1:]
	}

	for len(cs.Bounds) > 1 {
		if cs.Bounds[1].Start > now {
			// Remaining steps haven't started yet, so keep them and the current active one.
			break
		}

		cs.Bounds = cs.Bounds[1:]
	}
}

// amend changes the schedule to use new given steps, replacing steps that are fully covered in the amendment.
func (cs *CommissionSchedule) amend(amendment *CommissionSchedule) {
	if len(amendment.Rates) != 0 {
		rateSpliceIndex := 0
		for ; rateSpliceIndex < len(cs.Rates); rateSpliceIndex++ {
			if cs.Rates[rateSpliceIndex].Start >= amendment.Rates[0].Start {
				// This and remaining steps are completely overwritten by the amendment.
				break
			}
		}
		cs.Rates = append(cs.Rates[:rateSpliceIndex], amendment.Rates...)
	}

	if len(amendment.Bounds) != 0 {
		boundSpliceIndex := 0
		for ; boundSpliceIndex < len(cs.Bounds); boundSpliceIndex++ {
			if cs.Bounds[boundSpliceIndex].Start >= amendment.Bounds[0].Start {
				// This and remaining steps are completely overwritten by the amendment.
				break
			}
		}
		cs.Bounds = append(cs.Bounds[:boundSpliceIndex], amendment.Bounds...)
	}
}

// validateWithinBound detects rates out of bound.
func (cs *CommissionSchedule) validateWithinBound(now epochtime.EpochTime) error {
	if len(cs.Rates) == 0 && len(cs.Bounds) == 0 {
		// Nothing to check.
		return nil
	}

	if len(cs.Rates) == 0 {
		return fmt.Errorf("rates missing")
	}
	currentRateIndex := 0
	currentRate := &cs.Rates[currentRateIndex]

	if len(cs.Bounds) == 0 {
		return fmt.Errorf("bounds missing")
	}
	currentBoundIndex := 0
	currentBound := &cs.Bounds[currentBoundIndex]

	var diagnosticTime epochtime.EpochTime
	if currentRate.Start > now || currentBound.Start > now {
		// We only care if the two schedules start simultaneously if they will start in the future.
		// Steps that already started my have started at different times with older steps pruned.
		if currentRate.Start != currentBound.Start {
			return fmt.Errorf("rate schedule start epoch %d and bound schedule start epoch %d don't match", currentRate.Start, currentBound.Start)
		}
		diagnosticTime = currentRate.Start
	} else {
		diagnosticTime = now
	}

	for {
		if currentRate.Rate.Cmp(&currentBound.RateMin) < 0 {
			return fmt.Errorf("rate %v/%v from rate step %d less than minimum rate %v/%v from bound step %d at epoch %d",
				currentRate.Rate, CommissionRateDenominator, currentRateIndex,
				currentBound.RateMin, CommissionRateDenominator, currentBoundIndex,
				diagnosticTime,
			)
		}
		if currentRate.Rate.Cmp(&currentBound.RateMax) > 0 {
			return fmt.Errorf("rate %v/%v from rate step %d greater than maximum rate %v/%v from bound step %d at epoch %d",
				currentRate.Rate, CommissionRateDenominator, currentRateIndex,
				currentBound.RateMax, CommissionRateDenominator, currentBoundIndex,
				diagnosticTime,
			)
		}

		// Determine what changes next.
		nextRateIndex := currentRateIndex + 1
		var nextRate *CommissionRateStep
		if nextRateIndex < len(cs.Rates) {
			nextRate = &cs.Rates[nextRateIndex]
		} else {
			nextRate = nil
		}
		nextBoundIndex := currentBoundIndex + 1
		var nextBound *CommissionRateBoundStep
		if nextBoundIndex < len(cs.Bounds) {
			nextBound = &cs.Bounds[nextBoundIndex]
		} else {
			nextBound = nil
		}

		if nextRate == nil && nextBound == nil {
			// Current rate and bound continue happily ever after.
			break
		}

		if nextRate != nil {
			if nextBound == nil || nextRate.Start <= nextBound.Start {
				// Rate changes. Check with the new rate on next iteration.
				currentRateIndex = nextRateIndex
				currentRate = nextRate
				diagnosticTime = nextRate.Start
			}
		}

		if nextBound != nil {
			if nextRate == nil || nextBound.Start <= nextRate.Start {
				// Bound changes. Check with the new bound on the next iteration.
				currentBoundIndex = nextBoundIndex
				currentBound = nextBound
				diagnosticTime = nextBound.Start
			}
		}
	}

	return nil
}

// PruneAndValidateForGenesis gets a schedule ready for use in the genesis document.
// Returns an error if there is a validation failure. If it does, the schedule may be pruned already.
func (cs *CommissionSchedule) PruneAndValidateForGenesis(now epochtime.EpochTime, commissionRateChangeInterval epochtime.EpochTime, commissionScheduleMaxRateSteps int, commissionScheduleMaxBoundSteps int) error {
	if err := cs.validateComplexity(commissionScheduleMaxRateSteps, commissionScheduleMaxBoundSteps); err != nil {
		return err
	}
	if err := cs.validateNondegenerate(commissionRateChangeInterval); err != nil {
		return err
	}
	// If we, for example, import a snapshot as a genesis document, the current steps might not be cued up. So run a
	// prune step too at this time.
	cs.prune(now)
	if err := cs.validateWithinBound(now); err != nil {
		return errors.Wrap(err, "after pruning")
	}
	return nil
}

// AmendAndPruneAndValidate applies a proposed amendment to a valid schedule.
// Returns an error if there is a validation failure. If it does, the schedule may be amended and pruned already.
func (cs *CommissionSchedule) AmendAndPruneAndValidate(amendment *CommissionSchedule, now epochtime.EpochTime, commissionRateChangeInterval epochtime.EpochTime, commissionRateBoundLead epochtime.EpochTime, commissionScheduleMaxRateSteps int, commissionScheduleMaxBoundSteps int) error {
	if err := amendment.validateComplexity(commissionScheduleMaxRateSteps, commissionScheduleMaxBoundSteps); err != nil {
		return errors.Wrap(err, "amendment")
	}
	if err := amendment.validateNondegenerate(commissionRateChangeInterval); err != nil {
		return errors.Wrap(err, "amendment")
	}
	if err := amendment.validateAmendmentAcceptable(now, commissionRateBoundLead); err != nil {
		return errors.Wrap(err, "amendment")
	}
	cs.prune(now)
	cs.amend(amendment)
	if err := cs.validateComplexity(commissionScheduleMaxRateSteps, commissionScheduleMaxBoundSteps); err != nil {
		return errors.Wrap(err, "after pruning and amending")
	}
	if err := cs.validateWithinBound(now); err != nil {
		return errors.Wrap(err, "after pruning and amending")
	}
	return nil
}

// CurrentRate returns the rate at the latest rate step that has started or nil if no step has started.
func (cs *CommissionSchedule) CurrentRate(now epochtime.EpochTime) *quantity.Quantity {
	var latestStartedStep *CommissionRateStep
	for i := range cs.Rates {
		step := &cs.Rates[i]
		if step.Start > now {
			break
		}
		latestStartedStep = step
	}
	if latestStartedStep == nil {
		return nil
	}
	return &latestStartedStep.Rate
}

func init() {
	// Denominated in 1000th of a percent.
	CommissionRateDenominator = quantity.NewQuantity()
	err := CommissionRateDenominator.FromInt64(100_000)
	if err != nil {
		panic(err)
	}
}
