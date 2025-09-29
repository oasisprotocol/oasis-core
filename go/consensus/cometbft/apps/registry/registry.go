// Package registry implements the registry application.
package registry

import (
	"fmt"
	"math"

	"github.com/cometbft/cometbft/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	governanceApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/api"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// Application is a registry application.
type Application struct {
	state api.ApplicationState
	md    api.MessageDispatcher
}

// New constructs a new registry application.
func New(state api.ApplicationState, md api.MessageDispatcher) *Application {
	return &Application{
		state: state,
		md:    md,
	}
}

// Name implements api.Application.
func (app *Application) Name() string {
	return AppName
}

// ID implements api.Application.
func (app *Application) ID() uint8 {
	return AppID
}

// Methods implements api.Application.
func (app *Application) Methods() []transaction.MethodName {
	return registry.Methods
}

// Blessed implements api.Application.
func (app *Application) Blessed() bool {
	return false
}

// Dependencies implements api.Application.
func (app *Application) Dependencies() []string {
	return []string{stakingapp.AppName}
}

// Subscribe implements api.Application.
func (app *Application) Subscribe() {
	// Subscribe to messages emitted by other apps.
	app.md.Subscribe(roothashApi.RuntimeMessageRegistry, app)
	app.md.Subscribe(governanceApi.MessageChangeParameters, app)
	app.md.Subscribe(governanceApi.MessageValidateParameterChanges, app)
}

// OnCleanup implements api.Application.
func (app *Application) OnCleanup() {
}

// BeginBlock implements api.Application.
func (app *Application) BeginBlock(ctx *api.Context) error {
	// XXX: With PR#1889 this can be a differnet interval.
	if changed, registryEpoch := app.state.EpochChanged(ctx); changed {
		return app.onRegistryEpochChanged(ctx, registryEpoch)
	}
	return nil
}

// ExecuteMessage implements api.MessageSubscriber.
func (app *Application) ExecuteMessage(ctx *api.Context, kind, msg any) (any, error) {
	switch kind {
	case roothashApi.RuntimeMessageRegistry:
		m := msg.(*message.RegistryMessage)
		switch {
		case m.UpdateRuntime != nil:
			state := registryState.NewMutableState(ctx.State())
			return app.registerRuntime(ctx, state, m.UpdateRuntime)
		default:
			return nil, registry.ErrInvalidArgument
		}
	case governanceApi.MessageValidateParameterChanges:
		// A change parameters proposal is about to be submitted. Validate changes.
		return app.changeParameters(ctx, msg, false)
	case governanceApi.MessageChangeParameters:
		// A change parameters proposal has just been accepted and closed. Validate and apply
		// changes.
		return app.changeParameters(ctx, msg, true)
	default:
		return nil, registry.ErrInvalidArgument
	}
}

func (app *Application) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	state := registryState.NewMutableState(ctx.State())

	ctx.SetPriority(AppPriority)

	switch tx.Method {
	case registry.MethodRegisterEntity:
		var sigEnt entity.SignedEntity
		if err := cbor.Unmarshal(tx.Body, &sigEnt); err != nil {
			return registry.ErrInvalidArgument
		}
		return app.registerEntity(ctx, state, &sigEnt)

	case registry.MethodDeregisterEntity:
		return app.deregisterEntity(ctx, state)

	case registry.MethodRegisterNode:
		var sigNode node.MultiSignedNode
		if err := cbor.Unmarshal(tx.Body, &sigNode); err != nil {
			return registry.ErrInvalidArgument
		}
		ctx.SetPriority(AppPriority + 10000)
		return app.registerNode(ctx, state, &sigNode)

	case registry.MethodUnfreezeNode:
		var unfreeze registry.UnfreezeNode
		if err := cbor.Unmarshal(tx.Body, &unfreeze); err != nil {
			return registry.ErrInvalidArgument
		}
		return app.unfreezeNode(ctx, state, &unfreeze)

	case registry.MethodRegisterRuntime:
		var rt registry.Runtime
		if err := cbor.Unmarshal(tx.Body, &rt); err != nil {
			return registry.ErrInvalidArgument
		}
		if _, err := app.registerRuntime(ctx, state, &rt); err != nil {
			return err
		}
		return nil

	case registry.MethodProveFreshness:
		var blob [32]byte
		if err := cbor.Unmarshal(tx.Body, &blob); err != nil {
			ctx.Logger().Error("ExecuteTx: failed to unmarshal blob for freshness proof",
				"err", err,
			)
			return registry.ErrInvalidArgument
		}
		if err := app.proveFreshness(ctx, state); err != nil {
			return err
		}
		return nil

	default:
		return registry.ErrInvalidArgument
	}
}

func (app *Application) EndBlock(*api.Context) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *Application) onRegistryEpochChanged(ctx *api.Context, registryEpoch beacon.EpochTime) (err error) {
	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	nodes, err := regState.Nodes(ctx)
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

	params, err := stakeState.ConsensusParameters(ctx)
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
		if !node.IsExpired(registryEpoch) {
			continue
		}

		// Fetch node status to check whether we have already processed the
		// node expiration (this is required so that we don't emit expiration
		// events every epoch).
		var status *registry.NodeStatus
		status, err = regState.NodeStatus(ctx, node.ID)
		if err != nil {
			return fmt.Errorf("registry: onRegistryEpochChanged: couldn't get node status: %w", err)
		}

		if !status.ExpirationProcessed {
			expiredNodes = append(expiredNodes, node)
			status.ExpirationProcessed = true
			if err = regState.SetNodeStatus(ctx, node.ID, status); err != nil {
				return fmt.Errorf("registry: onRegistryEpochChanged: couldn't set node status: %w", err)
			}
		}

		// If node has been expired for the debonding interval, finally remove it.
		if math.MaxUint64-node.Expiration < debondingInterval {
			// Overflow, the node will never be removed.
			continue
		}
		if node.Expiration+debondingInterval < registryEpoch {
			ctx.Logger().Debug("removing expired node",
				"node_id", node.ID,
			)
			if err = regState.RemoveNode(ctx, node); err != nil {
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
