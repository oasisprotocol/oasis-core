package secrets

import (
	"errors"
	"fmt"

	"github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
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

	// TODO: The better thing to do would be to move the registry init
	// before the keymanager, and just query the registry for the runtime
	// list.
	regSt := doc.Registry
	rtMap := make(map[common.Namespace]*registry.Runtime)
	for _, rt := range regSt.Runtimes {
		err := registry.VerifyRuntime(&regSt.Parameters, ctx.Logger(), rt, true, false, epoch)
		if err != nil {
			ctx.Logger().Error("InitChain: Invalid runtime",
				"err", err,
			)
			continue
		}

		if rt.Kind == registry.KindKeyManager {
			rtMap[rt.ID] = rt
		}
	}

	var toEmit []*secrets.Status
	for i, v := range st.Statuses {
		if v == nil {
			return fmt.Errorf("InitChain: Status index %d is nil", i)
		}
		rt := rtMap[v.ID]
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
