// Package registry implements the registry application.
package registry

import (
	"fmt"
	"math"

	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/api"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var _ api.Application = (*registryApplication)(nil)

type registryApplication struct {
	state api.ApplicationState
	md    api.MessageDispatcher
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

func (app *registryApplication) OnRegister(state api.ApplicationState, md api.MessageDispatcher) {
	app.state = state
	app.md = md

	// Subscribe to messages emitted by other apps.
	md.Subscribe(roothashApi.RuntimeMessageRegistry, app)
}

func (app *registryApplication) OnCleanup() {
}

func (app *registryApplication) BeginBlock(ctx *api.Context, request types.RequestBeginBlock) error {
	// XXX: With PR#1889 this can be a differnet interval.
	if changed, registryEpoch := app.state.EpochChanged(ctx); changed {
		return app.onRegistryEpochChanged(ctx, registryEpoch)
	}
	return nil
}

func (app *registryApplication) ExecuteMessage(ctx *api.Context, kind, msg interface{}) (interface{}, error) {
	state := registryState.NewMutableState(ctx.State())

	switch kind {
	case roothashApi.RuntimeMessageRegistry:
		m := msg.(*message.RegistryMessage)
		switch {
		case m.UpdateRuntime != nil:
			return app.registerRuntime(ctx, state, m.UpdateRuntime)
		default:
			return nil, registry.ErrInvalidArgument
		}
	default:
		return nil, registry.ErrInvalidArgument
	}
}

func (app *registryApplication) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
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
		var sigNode node.MultiSignedNode
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
		var rt registry.Runtime
		if err := cbor.Unmarshal(tx.Body, &rt); err != nil {
			return err
		}
		if _, err := app.registerRuntime(ctx, state, &rt); err != nil {
			return err
		}
		return nil
	default:
		return registry.ErrInvalidArgument
	}
}

func (app *registryApplication) EndBlock(ctx *api.Context, request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *registryApplication) onRegistryEpochChanged(ctx *api.Context, registryEpoch beacon.EpochTime) (err error) {
	state := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	nodes, err := state.Nodes(ctx)
	if err != nil {
		ctx.Logger().Error("onRegistryEpochChanged: failed to get nodes",
			"err", err,
		)
		return fmt.Errorf("registry: onRegistryEpochChanged: failed to get nodes: %w", err)
	}

	debondingInterval, err := stakeState.DebondingInterval(ctx)
	if err != nil {
		ctx.Logger().Error("onRegistryEpochChanged: failed to get debonding interval",
			"err", err,
		)
		return fmt.Errorf("registry: onRegistryEpochChanged: failed to get debonding interval: %w", err)
	}

	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		ctx.Logger().Error("onRegistryEpochChanged: failed to fetch consensus parameters",
			"err", err,
		)
		return fmt.Errorf("registry: onRegistryEpochChanged: failed to fetch consensus parameters: %w", err)
	}

	var stakeAcc *stakingState.StakeAccumulatorCache
	if !params.DebugBypassStake {
		stakeAcc, err = stakingState.NewStakeAccumulatorCache(ctx)
		if err != nil {
			return fmt.Errorf("failed to create stake accumulator cache: %w", err)
		}
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
		status, err = state.NodeStatus(ctx, node.ID)
		if err != nil {
			return fmt.Errorf("registry: onRegistryEpochChanged: couldn't get node status: %w", err)
		}

		if !status.ExpirationProcessed {
			expiredNodes = append(expiredNodes, node)
			status.ExpirationProcessed = true
			if err = state.SetNodeStatus(ctx, node.ID, status); err != nil {
				return fmt.Errorf("registry: onRegistryEpochChanged: couldn't set node status: %w", err)
			}
		}

		// If node has been expired for the debonding interval, finally remove it.
		if math.MaxUint64-node.Expiration < uint64(debondingInterval) {
			// Overflow, the node will never be removed.
			continue
		}
		if beacon.EpochTime(node.Expiration)+debondingInterval < registryEpoch {
			ctx.Logger().Debug("removing expired node",
				"node_id", node.ID,
			)
			if err = state.RemoveNode(ctx, node); err != nil {
				return fmt.Errorf("registry: onRegistryEpochChanged: couldn't remove node: %w", err)
			}

			// Remove the stake claim for the given node.
			if !params.DebugBypassStake {
				acctAddr := staking.NewAddress(node.EntityID)
				if err = stakeAcc.RemoveStakeClaim(acctAddr, registry.StakeClaimForNode(node.ID)); err != nil {
					return fmt.Errorf("registry: onRegistryEpochChanged: couldn't remove stake claim: %w", err)
				}
			}
		}
	}

	if !params.DebugBypassStake {
		if err = stakeAcc.Commit(); err != nil {
			return fmt.Errorf("registry: onRegistryEpochChanged: failed to commit stake accumulator: %w", err)
		}
	}

	// Emit the expired node event for all expired nodes.
	for _, expiredNode := range expiredNodes {
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.NodeEvent{Node: expiredNode, IsRegistration: false}))
	}
	// Emit the node list epoch event.
	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&registry.NodeListEpochEvent{}))

	return nil
}

// New constructs a new registry application instance.
func New() api.Application {
	return &registryApplication{}
}
