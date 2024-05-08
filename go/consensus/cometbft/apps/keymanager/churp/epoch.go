package churp

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

func (ext *churpExt) onEpochChange(ctx *tmapi.Context, epoch beacon.EpochTime) error {
	// Query the runtime and node lists.
	state := churpState.NewMutableState(ctx.State())
	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes(ctx)

	for _, rt := range runtimes {
		statuses, err := state.Statuses(ctx, rt.ID)
		if err != nil {
			return fmt.Errorf("keymanager: churp: failed to fetch runtime statuses: %w", err)
		}

		for _, status := range statuses {
			if status.HandoffsDisabled() {
				continue
			}

			var completed bool

			switch epoch {
			case status.NextHandoff:
				// The epoch for the handoff just started, meaning that
				// application submissions are now closed. If not enough
				// nodes applied for the next committee, we need to reset
				// applications and start collecting again.
				if len(status.Applications) >= status.MinApplicants() {
					continue
				}
			case status.NextHandoff + 1:
				// The handoff epoch has ended. Not all nodes have reconstructed
				// and confirmed the share, as otherwise the next handoff epoch
				// would have been updated. Try to finalize it anyway.
				// If unsuccessful, reset and start collecting collecting again.
				completed = tryFinalizeHandoff(status, true)
			default:
				continue
			}

			if !completed {
				// The handoff failed. Start another one in the next epoch,
				// giving nodes one epoch time to submit applications.
				resetHandoff(status, epoch+1)
			}

			if err := state.SetStatus(ctx, status); err != nil {
				ctx.Logger().Error("keymanager: churp: failed to set status",
					"err", err,
				)
				return fmt.Errorf("keymanager: churp: failed to set status: %w", err)
			}

			ctx.EmitEvent(tmapi.NewEventBuilder(ext.appName).TypedAttribute(&churp.UpdateEvent{
				Status: status,
			}))
		}
	}

	return nil
}
