package keymanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	keymanagerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/keymanager/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func (app *keymanagerApplication) InitChain(ctx *tmapi.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.KeyManager

	b, _ := json.Marshal(st)
	ctx.Logger().Debug("InitChain: Genesis state",
		"state", string(b),
	)

	// TODO: The better thing to do would be to move the registry init
	// before the keymanager, and just query the registry for the runtime
	// list.
	regSt := doc.Registry
	rtMap := make(map[common.Namespace]*registry.Runtime)
	for _, rt := range regSt.Runtimes {
		err := registry.VerifyRuntime(&regSt.Parameters, ctx.Logger(), rt, true, false)
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

	var toEmit []*keymanager.Status
	state := keymanagerState.NewMutableState(ctx.State())
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
			return errors.New("tendermint/keymanager: genesis key manager has nodes")
		}

		// Set, enqueue for emit.
		if err := state.SetStatus(ctx, v); err != nil {
			return fmt.Errorf("tendermint/keymanager: failed to set status: %w", err)
		}
		toEmit = append(toEmit, v)
	}

	if len(toEmit) > 0 {
		ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).TypedAttribute(&keymanager.StatusUpdateEvent{
			Statuses: toEmit,
		}))
	}

	return nil
}

func (kq *keymanagerQuerier) Genesis(ctx context.Context) (*keymanager.Genesis, error) {
	statuses, err := kq.state.Statuses(ctx)
	if err != nil {
		return nil, err
	}

	// Remove the Nodes field of each Status.
	for _, status := range statuses {
		status.Nodes = nil
	}

	gen := keymanager.Genesis{Statuses: statuses}
	return &gen, nil
}
