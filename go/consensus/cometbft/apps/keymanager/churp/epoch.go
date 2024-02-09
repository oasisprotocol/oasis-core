package churp

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

func (ext *churpExt) onEpochChange(ctx *tmapi.Context, epoch beacon.EpochTime) error {
	state := churpState.NewMutableState(ctx.State())

	statuses, err := state.Statuses(ctx)
	if err != nil {
		return fmt.Errorf("keymanager: churp: failed to fetch statuses: %w", err)
	}

	for _, status := range statuses {
		if status.NextHandoff == churp.HandoffsDisabled {
			continue
		}

		switch epoch {
		case status.NextHandoff:
			// The epoch for the handoff just started, meaning that registrations
			// are now closed. If not enough nodes applied for the next committee,
			// we need to reset applications and start collecting again.
			minCommitteeSize := int(status.Threshold)*2 + 1
			if len(status.Applications) >= minCommitteeSize {
				continue
			}
		case status.NextHandoff + 1:
			// Handoff ended. Not all nodes replicated the secret and confirmed it,
			// as otherwise the next handoff epoch would be updated.
			// Reset and start collecting again
		default:
			continue
		}

		// The handoff failed, so postpone the round to the next epoch, giving
		// nodes one epoch time to submit applications.
		status.Applications = nil
		status.Checksum = nil
		status.NextHandoff = epoch + 1

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

	return nil
}
