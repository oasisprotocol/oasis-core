package registry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func (app *registryApplication) InitChain(ctx *abciAPI.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.Registry

	b, _ := json.Marshal(st)
	ctx.Logger().Debug("InitChain: Genesis state",
		"state", string(b),
	)

	epoch, err := app.state.GetCurrentEpoch(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/registry: couldn't get current epoch: %w", err)
	}

	state := registryState.NewMutableState(ctx.State())
	if err := state.SetConsensusParameters(ctx, &st.Parameters); err != nil {
		return fmt.Errorf("failed to set consensus parameters: %w", err)
	}

	for i, v := range st.Entities {
		if v == nil {
			return fmt.Errorf("registry: genesis entity index %d is nil", i)
		}
		ctx.Logger().Debug("InitChain: Registering genesis entity",
			"entity", v.Signature.PublicKey,
		)
		if err := app.registerEntity(ctx, state, v); err != nil {
			ctx.Logger().Error("InitChain: failed to register entity",
				"err", err,
				"entity", v,
			)
			return fmt.Errorf("registry: genesis entity registration failure: %w", err)
		}
	}
	// Register runtimes. First key manager and then compute runtime(s).
	for _, k := range []registry.RuntimeKind{registry.KindKeyManager, registry.KindCompute} {
		for i, rt := range st.Runtimes {
			if rt == nil {
				return fmt.Errorf("registry: genesis runtime index %d is nil", i)
			}
			err := registry.VerifyRuntime(&st.Parameters, ctx.Logger(), rt, ctx.IsInitChain(), false, epoch)
			if err != nil {
				return err
			}
			if rt.Kind != k {
				continue
			}
			ctx.Logger().Debug("InitChain: Registering genesis runtime",
				"runtime_id", rt.ID,
			)
			if _, err := app.registerRuntime(ctx, state, rt); err != nil {
				ctx.Logger().Error("InitChain: failed to register runtime",
					"err", err,
					"runtime_id", rt.ID,
				)
				return fmt.Errorf("registry: genesis runtime registration failure: %w", err)
			}
		}
	}
	for i, rt := range st.SuspendedRuntimes {
		if rt == nil {
			return fmt.Errorf("registry: genesis suspended runtime index %d is nil", i)
		}
		ctx.Logger().Debug("InitChain: Registering genesis suspended runtime",
			"runtime_id", rt.ID,
		)
		if _, err := app.registerRuntime(ctx, state, rt); err != nil {
			ctx.Logger().Error("InitChain: failed to register runtime",
				"err", err,
				"runtime_id", rt.ID,
			)
			return fmt.Errorf("registry: genesis suspended runtime registration failure: %w", err)
		}
		if err := state.SuspendRuntime(ctx, rt.ID); err != nil {
			return fmt.Errorf("registry: failed to suspend runtime at genesis: %w", err)
		}
	}
	for i, v := range st.Nodes {
		if v == nil {
			return fmt.Errorf("registry: genesis node index %d is nil", i)
		}
		// The node signer isn't guaranteed to be the owner, and in most cases
		// will just be the node self signing.
		ctx.Logger().Debug("InitChain: Registering genesis node",
			"node_signer", v.Signatures[0].PublicKey,
		)
		if err := app.registerNode(ctx, state, v); err != nil {
			ctx.Logger().Error("InitChain: failed to register node",
				"err", err,
				"node", v,
			)
			return fmt.Errorf("registry: genesis node registration failure: %w", err)
		}
	}

	for id, status := range st.NodeStatuses {
		if status == nil {
			return fmt.Errorf("registry: genesis node status %s is nil", id)
		}
		if err := state.SetNodeStatus(ctx, id, status); err != nil {
			ctx.Logger().Error("InitChain: failed to set node status",
				"err", err,
			)
			return fmt.Errorf("registry: genesis node status set failure: %w", err)
		}
	}

	return nil
}

func (rq *registryQuerier) Genesis(ctx context.Context) (*registry.Genesis, error) {
	// Fetch entities, runtimes, and nodes from state.
	signedEntities, err := rq.state.SignedEntities(ctx)
	if err != nil {
		return nil, err
	}
	runtimes, err := rq.state.Runtimes(ctx)
	if err != nil {
		return nil, err
	}
	suspendedRuntimes, err := rq.state.SuspendedRuntimes(ctx)
	if err != nil {
		return nil, err
	}
	signedNodes, err := rq.state.SignedNodes(ctx)
	if err != nil {
		return nil, err
	}

	// We only want to keep the nodes that are validators.
	//
	// BUG: If the debonding period will apply to other nodes,
	// then we need to basically persist everything.
	validatorNodes := make([]*node.MultiSignedNode, 0)
	nodeStatuses := make(map[signature.PublicKey]*registry.NodeStatus)
	for _, sn := range signedNodes {
		var n node.Node
		if err = cbor.Unmarshal(sn.Blob, &n); err != nil {
			return nil, err
		}

		if !n.HasRoles(node.RoleValidator) {
			continue
		}

		var status *registry.NodeStatus
		status, err = rq.state.NodeStatus(ctx, n.ID)
		if err != nil {
			return nil, err
		}

		validatorNodes = append(validatorNodes, sn)
		nodeStatuses[n.ID] = status
	}

	params, err := rq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	gen := registry.Genesis{
		Parameters:        *params,
		Entities:          signedEntities,
		Runtimes:          runtimes,
		SuspendedRuntimes: suspendedRuntimes,
		Nodes:             validatorNodes,
		NodeStatuses:      nodeStatuses,
	}
	return &gen, nil
}
