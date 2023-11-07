package roothash

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

const (
	// Backup worker round timeout stretch factor (15/10 = 1.5).
	backupWorkerTimeoutFactorNumerator   = 15
	backupWorkerTimeoutFactorDenominator = 10
)

func (app *rootHashApplication) processRoundTimeouts(ctx *tmapi.Context) error {
	state := roothashState.NewMutableState(ctx.State())

	roundTimeouts, err := state.RuntimesWithRoundTimeouts(ctx, ctx.BlockHeight()+1) // Current height is ctx.BlockHeight() + 1
	if err != nil {
		return fmt.Errorf("failed to fetch runtimes with round timeouts: %w", err)
	}

	for _, runtimeID := range roundTimeouts {
		if err = app.processRoundTimeout(ctx, runtimeID); err != nil {
			return fmt.Errorf("failed to process round timeout: %w", err)
		}
	}

	return nil
}

func (app *rootHashApplication) processRoundTimeout(ctx *tmapi.Context, runtimeID common.Namespace) error {
	ctx.Logger().Warn("round timeout expired, forcing finalization",
		"runtime_id", runtimeID,
		logging.LogEvent, roothash.LogEventTimerFired,
	)

	if err := app.tryFinalizeRound(ctx, runtimeID, true); err != nil {
		ctx.Logger().Error("failed to finalize round",
			"runtime_id", runtimeID,
			"err", err,
		)
		return fmt.Errorf("failed to finalize round: %w", err)
	}

	return nil
}

func rearmRoundTimeout(ctx *tmapi.Context, runtimeID common.Namespace, round uint64, prevTimeout int64, nextTimeout int64) error {
	// Re-arm only if the round timeout has changed.
	if prevTimeout == nextTimeout {
		return nil
	}

	ctx.Logger().Debug("re-arming round timeout",
		"runtime_id", runtimeID,
		"round", round,
		"prev_timeout", prevTimeout,
		"next_timeout", nextTimeout,
		"height", ctx.BlockHeight()+1, // Current height is ctx.BlockHeight() + 1
	)

	state := roothashState.NewMutableState(ctx.State())

	if prevTimeout != roothash.TimeoutNever {
		if err := state.ClearRoundTimeout(ctx, runtimeID, prevTimeout); err != nil {
			return fmt.Errorf("failed to clear round timeout: %w", err)
		}
	}

	if nextTimeout != roothash.TimeoutNever {
		if err := state.ScheduleRoundTimeout(ctx, runtimeID, nextTimeout); err != nil {
			return fmt.Errorf("failed to schedule round timeout: %w", err)
		}
	}

	return nil
}
