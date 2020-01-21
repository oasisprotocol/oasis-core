// Package registry implements the registry application.
package registry

import (
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var _ abci.Application = (*registryApplication)(nil)

type registryApplication struct {
	state *abci.ApplicationState
}

func (app *registryApplication) Name() string {
	return AppName
}

func (app *registryApplication) ID() uint8 {
	return AppID
}

func (app *registryApplication) Methods() []transaction.MethodName {
	return registry.Methods
}

func (app *registryApplication) Blessed() bool {
	return false
}

func (app *registryApplication) Dependencies() []string {
	return []string{stakingapp.AppName}
}

func (app *registryApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *registryApplication) OnCleanup() {
}

func (app *registryApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// XXX: With PR#1889 this can be a differnet interval.
	if changed, registryEpoch := app.state.EpochChanged(ctx); changed {
		return app.onRegistryEpochChanged(ctx, registryEpoch)
	}
	return nil
}

func (app *registryApplication) ExecuteTx(ctx *abci.Context, tx *transaction.Transaction) error {
	state := registryState.NewMutableState(ctx.State())

	switch tx.Method {
	case registry.MethodRegisterEntity:
		var sigEnt entity.SignedEntity
		if err := cbor.Unmarshal(tx.Body, &sigEnt); err != nil {
			return err
		}

		return app.registerEntity(ctx, state, &sigEnt)
	case registry.MethodDeregisterEntity:
		return app.deregisterEntity(ctx, state)
	case registry.MethodRegisterNode:
		var sigNode node.SignedNode
		if err := cbor.Unmarshal(tx.Body, &sigNode); err != nil {
			return err
		}

		return app.registerNode(ctx, state, &sigNode)
	case registry.MethodUnfreezeNode:
		var unfreeze registry.UnfreezeNode
		if err := cbor.Unmarshal(tx.Body, &unfreeze); err != nil {
			return err
		}

		return app.unfreezeNode(ctx, state, &unfreeze)
	case registry.MethodRegisterRuntime:
		var sigRt registry.SignedRuntime
		if err := cbor.Unmarshal(tx.Body, &sigRt); err != nil {
			return err
		}

		params, err := state.ConsensusParameters()
		if err != nil {
			ctx.Logger().Error("RegisterRuntime: failed to fetch consensus parameters",
				"err", err,
			)
			return err
		}

		if !params.DebugAllowRuntimeRegistration {
			return registry.ErrForbidden
		}
		return app.registerRuntime(ctx, state, &sigRt)
	default:
		return registry.ErrInvalidArgument
	}
}

func (app *registryApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx *transaction.Transaction) error {
	return nil
}

func (app *registryApplication) EndBlock(ctx *abci.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *registryApplication) FireTimer(*abci.Context, *abci.Timer) error {
	return fmt.Errorf("tendermint/registry: unexpected timer")
}

func (app *registryApplication) onRegistryEpochChanged(ctx *abci.Context, registryEpoch epochtime.EpochTime) error {
	state := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	nodes, err := state.Nodes()
	if err != nil {
		ctx.Logger().Error("onRegistryEpochChanged: failed to get nodes",
			"err", err,
		)
		return fmt.Errorf("registry: onRegistryEpochChanged: failed to get nodes: %w", err)
	}

	debondingInterval, err := stakeState.DebondingInterval()
	if err != nil {
		ctx.Logger().Error("onRegistryEpochChanged: failed to get debonding interval",
			"err", err,
		)
		return fmt.Errorf("registry: onRegistryEpochChanged: failed to get debonding interval: %w", err)
	}

	// When a node expires, it is kept around for up to the debonding
	// period and then removed. This is required so that expired nodes
	// can still get slashed while inside the debonding interval as
	// otherwise the nodes could not be resolved.
	var expiredNodes []*node.Node
	for _, node := range nodes {
		if !node.IsExpired(uint64(registryEpoch)) {
			continue
		}

		// Fetch node status to check whether we have already processed the
		// node expiration (this is required so that we don't emit expiration
		// events every epoch).
		var status *registry.NodeStatus
		status, err = state.NodeStatus(node.ID)
		if err != nil {
			return fmt.Errorf("registry: onRegistryEpochChanged: couldn't get node status: %w", err)
		}

		if !status.ExpirationProcessed {
			expiredNodes = append(expiredNodes, node)
			status.ExpirationProcessed = true
			if err = state.SetNodeStatus(node.ID, status); err != nil {
				return fmt.Errorf("registry: onRegistryEpochChanged: couldn't set node status: %w", err)
			}
		}

		// If node has been expired for the debonding interval, finally remove it.
		if epochtime.EpochTime(node.Expiration)+debondingInterval < registryEpoch {
			ctx.Logger().Debug("removing expired node",
				"node_id", node.ID,
			)
			state.RemoveNode(node)
		}
	}

	// Emit the RegistryNodeListEpoch notification event.
	evb := api.NewEventBuilder(app.Name())
	// (Dummy value, should be ignored.)
	evb = evb.Attribute(KeyRegistryNodeListEpoch, []byte("1"))

	if len(expiredNodes) > 0 {
		// Iff any nodes have expired, force-emit the NodesExpired event
		// so the change is picked up.
		evb = evb.Attribute(KeyNodesExpired, cbor.Marshal(expiredNodes))
	}

	ctx.EmitEvent(evb)

	return nil
}

// New constructs a new registry application instance.
func New() abci.Application {
	return &registryApplication{}
}
