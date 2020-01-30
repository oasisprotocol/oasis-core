package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

func (app *registryApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.Registry

	b, _ := json.Marshal(st)
	ctx.Logger().Debug("InitChain: Genesis state",
		"state", string(b),
	)

	state := registryState.NewMutableState(ctx.State())
	state.SetConsensusParameters(&st.Parameters)

	if st.Parameters.KeyManagerOperator.IsValid() {
		ctx.Logger().Debug("InitChain: Registering key manager operator",
			"id", st.Parameters.KeyManagerOperator,
		)
	} else {
		// This is informational for now since there are configurations
		// that do not have a key manager.
		ctx.Logger().Warn("InitChain: Invalid key manager operator, key manager will not work",
			"id", st.Parameters.KeyManagerOperator,
		)
	}

	for _, v := range st.Entities {
		ctx.Logger().Debug("InitChain: Registering genesis entity",
			"entity", v.Signature.PublicKey,
		)
		if err := app.registerEntity(ctx, state, v); err != nil {
			ctx.Logger().Error("InitChain: failed to register entity",
				"err", err,
				"entity", v,
			)
			return errors.Wrap(err, "registry: genesis entity registration failure")
		}
	}
	// Register runtimes. First key manager and then compute runtime(s).
	for _, k := range []registry.RuntimeKind{registry.KindKeyManager, registry.KindCompute} {
		for _, v := range st.Runtimes {
			rt, err := registry.VerifyRegisterRuntimeArgs(&st.Parameters, ctx.Logger(), v, ctx.IsInitChain())
			if err != nil {
				return err
			}
			if rt.Kind != k {
				continue
			}
			ctx.Logger().Debug("InitChain: Registering genesis runtime",
				"runtime_owner", v.Signature.PublicKey,
			)
			if err := app.registerRuntime(ctx, state, v); err != nil {
				ctx.Logger().Error("InitChain: failed to register runtime",
					"err", err,
					"runtime", v,
				)
				return errors.Wrap(err, "registry: genesis runtime registration failure")
			}
		}
	}
	for _, v := range st.SuspendedRuntimes {
		ctx.Logger().Debug("InitChain: Registering genesis suspended runtime",
			"runtime_owner", v.Signature.PublicKey,
		)
		if err := app.registerRuntime(ctx, state, v); err != nil {
			ctx.Logger().Error("InitChain: failed to register runtime",
				"err", err,
				"runtime", v,
			)
			return errors.Wrap(err, "registry: genesis suspended runtime registration failure")
		}
		var rt registry.Runtime
		if err := cbor.Unmarshal(v.Blob, &rt); err != nil {
			return errors.Wrap(err, "registry: malformed genesis suspended runtime")
		}
		if err := state.SuspendRuntime(rt.ID); err != nil {
			return errors.Wrap(err, "registry: failed to suspend runtime at genesis")
		}
	}
	for _, v := range st.Nodes {
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
			return errors.Wrap(err, "registry: genesis node registration failure")
		}
	}

	type nodeStatus struct {
		id     signature.PublicKey
		status *registry.NodeStatus
	}
	var ns []*nodeStatus
	for k, v := range st.NodeStatuses {
		ns = append(ns, &nodeStatus{k, v})
	}
	// Make sure that we apply node status updates in a canonical order.
	sort.SliceStable(ns, func(i, j int) bool { return bytes.Compare(ns[i].id[:], ns[j].id[:]) < 0 })
	for _, s := range ns {
		if err := state.SetNodeStatus(s.id, s.status); err != nil {
			ctx.Logger().Error("InitChain: failed to set node status",
				"err", err,
			)
			return errors.Wrap(err, "registry: genesis node status set failure")
		}
	}

	return nil
}

func (rq *registryQuerier) Genesis(ctx context.Context) (*registry.Genesis, error) {
	// Fetch entities, runtimes, and nodes from state.
	signedEntities, err := rq.state.SignedEntities()
	if err != nil {
		return nil, err
	}
	signedRuntimes, err := rq.state.SignedRuntimes()
	if err != nil {
		return nil, err
	}
	suspendedRuntimes, err := rq.state.SuspendedRuntimes()
	if err != nil {
		return nil, err
	}
	signedNodes, err := rq.state.SignedNodes()
	if err != nil {
		return nil, err
	}

	// We only want to keep the nodes that are validators.
	//
	// BUG: If the debonding period will apply to other nodes,
	// then we need to basically persist everything.
	validatorNodes := make([]*node.MultiSignedNode, 0)
	for _, sn := range signedNodes {
		var n node.Node
		if err = cbor.Unmarshal(sn.Blob, &n); err != nil {
			return nil, err
		}

		if n.HasRoles(node.RoleValidator) {
			validatorNodes = append(validatorNodes, sn)
		}
	}

	nodeStatuses, err := rq.state.NodeStatuses()
	if err != nil {
		return nil, err
	}

	params, err := rq.state.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	gen := registry.Genesis{
		Parameters:        *params,
		Entities:          signedEntities,
		Runtimes:          signedRuntimes,
		SuspendedRuntimes: suspendedRuntimes,
		Nodes:             validatorNodes,
		NodeStatuses:      nodeStatuses,
	}
	return &gen, nil
}
