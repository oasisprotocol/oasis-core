package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// NameCommission is the name of the commission schedule amendements
	// workload.
	NameCommission = "commission"

	// Max number of rate change intervals between two bound steps.
	commissionMaxBoundChangeIntervals = 10
	// Max number of rate change intervals between two rate steps.
	commissionMaxRateChangeIntervals = 10
)

type commission struct {
	logger *logging.Logger

	rules          staking.CommissionScheduleRules
	signer         signature.Signer
	address        staking.Address
	reckonedNonce  uint64
	fundingAccount signature.Signer
}

// currentBound returns the rate bounds at the latest bound step that has
// started or nil if no step has started.
func currentBound(cs *staking.CommissionSchedule, now epochtime.EpochTime) *staking.CommissionRateBoundStep {
	var latestStartedStep *staking.CommissionRateBoundStep
	for i := range cs.Bounds {
		step := &cs.Bounds[i]
		if step.Start > now {
			break
		}
		latestStartedStep = step
	}
	return latestStartedStep
}

// genValidRateStep generates a commission rate step that conforms to all bound
// rules between start and end epoch. The function panics in case a rate step
// cannot satisfy all bound rules so the caller should make sure that bounds
// are not exclusive.
func genValidRateStep(rng *rand.Rand, logger *logging.Logger, schedule staking.CommissionSchedule, startEpoch epochtime.EpochTime, endEpoch epochtime.EpochTime) staking.CommissionRateStep {
	startBound := currentBound(&schedule, startEpoch)
	minBound := startBound.RateMin.ToBigInt().Int64()
	maxBound := startBound.RateMax.ToBigInt().Int64()
	for _, bound := range schedule.Bounds {
		// Skip bounds before start bound.
		if bound.Start <= startBound.Start {
			continue
		}
		// Stop in case a bound after end is reached.
		if bound.Start >= endEpoch {
			break
		}
		boundMin := bound.RateMin.ToBigInt().Int64()
		boundMax := bound.RateMax.ToBigInt().Int64()
		if minBound < boundMin {
			minBound = boundMin
		}
		if maxBound > boundMax {
			maxBound = boundMax
		}
	}

	if minBound > maxBound {
		logger.Error("genValidRateStep: cannot satisfy all bound rules",
			"min_bound", minBound,
			"max_bound", maxBound,
			"start_epoch", startEpoch,
			"end_epoch", endEpoch,
			"schedule", schedule,
		)
		panic("genValidRateStep: cannot satisfy all bound rules!")
	}

	// [minBound, maxBound]
	rate := rng.Int63n(maxBound-minBound+1) + minBound
	step := staking.CommissionRateStep{Start: startEpoch}
	_ = step.Rate.FromInt64(rate)

	return step
}

// findNextExclusiveBound finds the next Bound step that has bounds which are
// exclusive with current bound step. Returns nil in case there is no exclusive
// bound step.
func findNextExclusiveBound(bounds []staking.CommissionRateBoundStep, currentBound *staking.CommissionRateBoundStep) *staking.CommissionRateBoundStep {
	currentMin := currentBound.RateMin
	currentMax := currentBound.RateMax
	for _, bound := range bounds {
		if bound.Start <= currentBound.Start {
			continue
		}
		// newMin > currentMax || newMax < currentMin
		if bound.RateMin.Cmp(&currentMax) == 1 || bound.RateMax.Cmp(&currentMin) == -1 {
			return &bound
		}
		// Update bounds.
		// newMin > currentMin
		if bound.RateMin.Cmp(&currentMin) == 1 {
			currentMin = bound.RateMin
		}
		// newMax < currentMax
		if bound.RateMax.Cmp(&currentMax) == -1 {
			currentMax = bound.RateMax
		}
	}
	return nil
}

func (c *commission) doAmendCommissionSchedule(ctx context.Context, rng *rand.Rand, cnsc consensus.ClientBackend, stakingClient staking.Backend) error {
	c.logger.Debug("amend commission schedule")

	// Get current epoch.
	currentEpoch, err := cnsc.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("GetEpoch: %w", err)
	}

	var account *staking.Account
	account, err = stakingClient.Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  c.address,
	})
	if err != nil {
		return fmt.Errorf("stakingClient.Account %s: %w", c.address, err)
	}
	existingCommissionSchedule := account.Escrow.CommissionSchedule
	existingCommissionSchedule.Prune(currentEpoch)

	// First epoch at which bound steps can be altered is
	// `currentEpoch + RateBoundLead + 1`
	// Note: Another +1 bellow since the epoch could have changed before this
	// transaction is submitted.
	nextAllowedBoundChangeEpoch := currentEpoch + c.rules.RateBoundLead + 1 + 1
	// Find first epoch after `nextAllowedBoundChangeEpoch` aligned with
	// RateChangeInterval.
	nextAlignedBoundChangeEpoch := (((nextAllowedBoundChangeEpoch - 1) / c.rules.RateChangeInterval) + 1) * c.rules.RateChangeInterval

	// Check existing bound steps. In case there are existing steps for epoch
	// before `nextAlignedBoundChangeEpoch`, those cannot get amended and also
	// won't be pruned yet. Therefore we need to count those to not go over the
	// max rules allowed limit.
	maxBoundSteps := c.rules.MaxBoundSteps
	for _, step := range existingCommissionSchedule.Bounds {
		if step.Start < nextAlignedBoundChangeEpoch {
			maxBoundSteps--
			continue
		}
		break
	}

	// Generate bound steps.
	// [1, maxBoundSteps]
	nBoundSteps := rng.Intn(int(maxBoundSteps)) + 1
	var amendSchedule staking.AmendCommissionSchedule
	boundEpoch := nextAlignedBoundChangeEpoch
	for i := 0; i < nBoundSteps; i++ {
		// [10, 100_000]
		maxBound := rng.Int63n(100_000-10+1) + 10
		// [0, maxBound]
		minBound := rng.Int63n(maxBound + 1)

		bound := staking.CommissionRateBoundStep{
			Start: boundEpoch,
		}
		if err = bound.RateMin.FromInt64(minBound); err != nil {
			return fmt.Errorf("Rate.FromInt64 err: %w", err)
		}
		if err = bound.RateMax.FromInt64(maxBound); err != nil {
			return fmt.Errorf("Rate.FromInt64 err: %w", err)
		}
		amendSchedule.Amendment.Bounds = append(amendSchedule.Amendment.Bounds, bound)

		// Set epoch for next bound.
		boundEpoch = boundEpoch + (epochtime.EpochTime(rng.Intn(commissionMaxBoundChangeIntervals)+1) * c.rules.RateChangeInterval)
	}

	// newSchedule is a schedule that contains all bounds that will be in effect
	// once the amendment will be submitted. It contains existing bounds that
	// are not yet pruned and won't be amended, and new bounds that will be
	// added.
	var newSchedule staking.CommissionSchedule
	// Keep existing steps that wont be amended.
	for _, bound := range existingCommissionSchedule.Bounds {
		if bound.Start >= amendSchedule.Amendment.Bounds[0].Start {
			break
		}
		newSchedule.Bounds = append(newSchedule.Bounds, bound)
	}
	// Add new steps.
	newSchedule.Bounds = append(newSchedule.Bounds, amendSchedule.Amendment.Bounds...)

	// Generate rate steps.
	// First epoch on which rule steps can be altered is the next epoch.
	// Note: Another +1 bellow since the epoch could have changed before this
	// transaction is submitted.
	nextAllowedRateChangeEpoch := currentEpoch + 1 + 1
	// Find first epoch after nextAllowedRateChangeEpoch aligned with
	// RateChangeInterval.
	nextAlignedRateChangeEpoch := (((nextAllowedRateChangeEpoch - 1) / c.rules.RateChangeInterval) + 1) * c.rules.RateChangeInterval
	// Rate start epoch.
	startEpoch := nextAlignedRateChangeEpoch
	// In the case when there are no existing bound steps (or none yet active),
	// the startEpoch needs to match the first bound rule epoch.
	if len(existingCommissionSchedule.Bounds) == 0 || existingCommissionSchedule.Bounds[0].Start > (currentEpoch+1) {
		startEpoch = newSchedule.Bounds[0].Start
	} else if startEpoch > amendSchedule.Amendment.Bounds[0].Start {
		// Else if there are already active rules, make sure that the initial
		// rule epoch is not greater than the initial bound epoch. Otherwise the
		// initial bound rule could invalidate an existing rate rule.
		startEpoch = amendSchedule.Amendment.Bounds[0].Start
	}
	// Check existing rate steps. In case there are existing steps for epoch
	// before `startEpoch`, those cannot get amended and also won't be pruned
	// yet. Therefore we need to count those to not go over the max rules
	// allowed limit.
	maxRateSteps := c.rules.MaxRateSteps
	for _, step := range existingCommissionSchedule.Rates {
		if step.Start < startEpoch {
			maxRateSteps--
			continue
		}
		break
	}
	// [1, maxRateSteps]
	nMinRateSteps := rng.Intn(int(maxRateSteps)) + 1

	// In some cases we might need more rate steps to satisfy all bound steps.
	var needMoreRateStpes bool
	for i := 0; i < nMinRateSteps || needMoreRateStpes; i++ {
		// startEpoch + rng[1, commissionMaxRateChangeIntervals]*RateChangeInterval
		endEpoch := startEpoch + (epochtime.EpochTime(rng.Intn(commissionMaxRateChangeIntervals)+1) * c.rules.RateChangeInterval)

		// Get active bound at start epoch.
		currentBound := currentBound(&newSchedule, startEpoch)
		if currentBound == nil {
			// This is not expected to ever happen.
			c.logger.Error("no active bound at epoch",
				"epoch", startEpoch,
				"schedule", newSchedule,
			)
			return fmt.Errorf("txsource/commission: no active bound")
		}
		// Find first following exclusive bound.
		nextBound := findNextExclusiveBound(newSchedule.Bounds, currentBound)
		c.logger.Debug("finding next exclusive bound",
			"current_bound", currentBound,
			"epoch", startEpoch,
			"end_epoch", endEpoch,
			"bounds", newSchedule.Bounds,
			"next_bound", nextBound,
			"need_more", needMoreRateStpes,
		)
		switch nextBound {
		case nil:
			// No exclusive bounds, endEpoch can remain as it is.
			// No more rate steps needed.
			needMoreRateStpes = false
			// If we are in last step and no exclusive bounds remain, generate
			// a rate that will satisfy all remaining bounds.
			if i >= nMinRateSteps-1 {
				endEpoch = newSchedule.Bounds[len(newSchedule.Bounds)-1].Start + 1
			}
		default:
			// There is an exclusive bound at nextBound.Start.
			// This rule can be valid for at most until nextBound.Start.
			if endEpoch > nextBound.Start {
				endEpoch = nextBound.Start
			}
			// More steps are needed to satisfy remaining bounds.
			needMoreRateStpes = true
		}

		c.logger.Debug("Generating valid rate step",
			"start_epoch", startEpoch,
			"end_epoch", endEpoch,
			"bounds", newSchedule.Bounds,
			"need_more", needMoreRateStpes,
		)
		step := genValidRateStep(rng, c.logger, newSchedule, startEpoch, endEpoch)
		amendSchedule.Amendment.Rates = append(amendSchedule.Amendment.Rates, step)

		// Next rate should start at endEpoch.
		startEpoch = endEpoch
	}

	// In some cases the above procedure can produce invalid amendment.
	// This happens when more than number of allowed amendment rate steps are
	// needed to satisfy all bound steps.
	if len(amendSchedule.Amendment.Rates) > int(maxRateSteps) {
		c.logger.Debug("To many rate steps needed to satisfy bonds, skipping amendment",
			"amendment", amendSchedule,
		)
		return nil
	}

	// Generate transaction.
	tx := staking.NewAmendCommissionScheduleTx(c.reckonedNonce, &transaction.Fee{}, &amendSchedule)
	c.reckonedNonce++

	// Estimate gas.
	gas, err := cnsc.EstimateGas(ctx, &consensus.EstimateGasRequest{
		Caller:      c.signer.Public(),
		Transaction: tx,
	})
	if err != nil {
		return fmt.Errorf("failed to estimate gas: %w", err)
	}
	tx.Fee.Gas = gas
	feeAmount := int64(gas) * gasPrice
	if err = tx.Fee.Amount.FromInt64(feeAmount); err != nil {
		return fmt.Errorf("fee amount from int64: %w", err)
	}

	// Fund account to cover AmendCommissionSchedule transaction fees.
	fundAmount := int64(gas) * gasPrice // transaction costs
	if err = transferFunds(ctx, c.logger, cnsc, c.fundingAccount, c.address, fundAmount); err != nil {
		return fmt.Errorf("account funding failure: %w", err)
	}

	// Sign transaction.
	signedTx, err := transaction.Sign(c.signer, tx)
	if err != nil {
		return fmt.Errorf("transaction.Sign: %w", err)
	}

	c.logger.Debug("submitting amend commission schedule transaction",
		"signer", c.signer.Public(),
		"account", c.address,
		"amendment", amendSchedule,
		"existing", existingCommissionSchedule,
	)

	// Submit transaction.
	if err = cnsc.SubmitTx(ctx, signedTx); err != nil {
		return fmt.Errorf("cnsc.SubmitTx: %w", err)
	}

	return nil
}

func (c *commission) Run(gracefulExit context.Context, rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, fundingAccount signature.Signer) error {
	var err error
	ctx := context.Background()

	c.logger = logging.GetLogger("cmd/txsource/workload/commission")
	c.fundingAccount = fundingAccount

	fac := memorySigner.NewFactory()
	c.signer, err = fac.Generate(signature.SignerEntity, rng)
	if err != nil {
		return fmt.Errorf("memory signer factory Generate account: %w", err)
	}
	c.address = staking.NewAddress(c.signer.Public())

	stakingClient := staking.NewStakingClient(conn)

	params, err := stakingClient.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("stakingClient.ConsensusParameters failure: %w", err)
	}
	c.rules = params.CommissionScheduleRules

	for {
		if err = c.doAmendCommissionSchedule(ctx, rng, cnsc, stakingClient); err != nil {
			return err
		}

		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			c.logger.Debug("time's up")
			return nil
		}
	}
}
