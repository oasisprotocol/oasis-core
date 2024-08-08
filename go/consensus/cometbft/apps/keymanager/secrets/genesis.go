package secrets

import (
	"errors"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/common"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

func (ext *secretsExt) InitChain(ctx *tmapi.Context, _ types.RequestInitChain, doc *genesis.Document) error {
	st := doc.KeyManager

	state := secretsState.NewMutableState(ctx.State())

	if err := state.SetConsensusParameters(ctx, &st.Parameters); err != nil {
		return fmt.Errorf("cometbft/keymanager: failed to set consensus parameters: %w", err)
	}

	epoch, err := ext.state.GetCurrentEpoch(ctx)
	if err != nil {
		return fmt.Errorf("cometbft/keymanager: couldn't get current epoch: %w", err)
	}
	runtimes := common.RegistryRuntimes(ctx, doc, epoch)

	var toEmit []*secrets.Status
	for i, v := range st.Statuses {
		if v == nil {
			return fmt.Errorf("InitChain: Status index %d is nil", i)
		}
		rt := runtimes[v.ID]
		if rt == nil {
			ctx.Logger().Error("InitChain: State for unknown key manager runtime",
				"id", v.ID,
			)
			continue
		}

		ctx.Logger().Debug("InitChain: Registering genesis key manager",
			"id", v.ID,
		)

		// Make sure the Nodes field is empty when applying genesis state.
		if v.Nodes != nil {
			ctx.Logger().Error("InitChain: Genesis key manager has nodes",
				"id", v.ID,
			)
			return errors.New("cometbft/keymanager: genesis key manager has nodes")
		}

		// Set, enqueue for emit.
		if err := state.SetStatus(ctx, v); err != nil {
			return fmt.Errorf("cometbft/keymanager: failed to set status: %w", err)
		}
		toEmit = append(toEmit, v)
	}

	if len(toEmit) > 0 {
		ctx.EmitEvent(tmapi.NewEventBuilder(ext.appName).TypedAttribute(&secrets.StatusUpdateEvent{
			Statuses: toEmit,
		}))
	}

	return nil
}
