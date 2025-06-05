package churp

import (
	"context"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/common"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

// InitChain implements api.Extension.
func (ext *churpExt) InitChain(ctx *tmapi.Context, _ types.RequestInitChain, doc *genesis.Document) error {
	// Ensure compatibility with Eden genesis file.
	st := doc.KeyManager.Churp
	if st == nil {
		return nil
	}

	// Insert consensus parameters.
	state := churpState.NewMutableState(ctx.State())
	if err := state.SetConsensusParameters(ctx, &churp.DefaultConsensusParameters); err != nil {
		return fmt.Errorf("cometbft/keymanager/churp: failed to set consensus parameters: %w", err)
	}

	// Fetch runtimes.
	epoch, err := ext.state.GetCurrentEpoch(ctx)
	if err != nil {
		return fmt.Errorf("cometbft/keymanager/churp: failed to get current epoch: %w", err)
	}
	runtimes := common.RegistryRuntimes(ctx, doc, epoch)

	// Insert statuses.
	for _, status := range st.Statuses {
		if _, ok := runtimes[status.RuntimeID]; !ok {
			return fmt.Errorf("cometbft/keymanager/churp: unknown key manager runtime: %s", status.RuntimeID)
		}

		// Disable handoffs for all instances.
		status.NextHandoff = churp.HandoffsDisabled
		status.NextChecksum = nil
		status.Applications = nil

		// Schedule the next handoff at the beginning of the next epoch.
		if status.HandoffInterval != 0 {
			status.NextHandoff = epoch + 1
		}

		if err := state.SetStatus(ctx, status); err != nil {
			return fmt.Errorf("cometbft/keymanager/churp: failed to set status: %w", err)
		}

		ctx.EmitEvent(tmapi.NewEventBuilder(ext.appName).TypedAttribute(&churp.UpdateEvent{
			Status: status,
		}))
	}

	return nil
}

// Genesis implements churp.Query.
func (q *Query) Genesis(ctx context.Context) (*churp.Genesis, error) {
	parameters, err := q.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	statuses, err := q.state.AllStatuses(ctx)
	if err != nil {
		return nil, err
	}

	// Disable handoffs for all instances.
	for _, status := range statuses {
		status.NextHandoff = churp.HandoffsDisabled
		status.NextChecksum = nil
		status.Applications = nil
	}

	gen := churp.Genesis{
		Parameters: *parameters,
		Statuses:   statuses,
	}
	return &gen, nil
}
