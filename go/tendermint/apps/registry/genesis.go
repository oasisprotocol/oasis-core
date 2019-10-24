package registry

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/node"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

func (app *registryApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.Registry

	b, _ := json.Marshal(st)
	app.logger.Debug("InitChain: Genesis state",
		"state", string(b),
	)

	state := NewMutableState(ctx.State())

	state.setKeyManagerOperator(st.KeyManagerOperator)
	app.logger.Debug("InitChain: Registering key manager operator",
		"id", st.KeyManagerOperator,
	)

	for _, v := range st.Entities {
		app.logger.Debug("InitChain: Registering genesis entity",
			"entity", v.Signature.PublicKey,
		)
		if err := app.registerEntity(ctx, state, v); err != nil {
			app.logger.Error("InitChain: failed to register entity",
				"err", err,
				"entity", v,
			)
			return errors.Wrap(err, "registry: genesis entity registration failure")
		}
	}
	for _, v := range st.Runtimes {
		app.logger.Debug("InitChain: Registering genesis runtime",
			"runtime_owner", v.Signature.PublicKey,
		)
		if err := app.registerRuntime(ctx, state, v); err != nil {
			app.logger.Error("InitChain: failed to register runtime",
				"err", err,
				"runtime", v,
			)
			return errors.Wrap(err, "registry: genesis runtime registration failure")
		}
	}
	for _, v := range st.Nodes {
		app.logger.Debug("InitChain: Registering genesis node",
			"node_owner", v.Signature.PublicKey,
		)
		if err := app.registerNode(ctx, state, v); err != nil {
			app.logger.Error("InitChain: failed to register node",
				"err", err,
				"node", v,
			)
			return errors.Wrap(err, "registry: genesis node registration failure")
		}
	}

	return nil
}

func (rq *registryQuerier) Genesis(ctx context.Context) (*registry.Genesis, error) {
	// Fetch entities, runtimes, and nodes from state.
	signedEntities, err := rq.state.getSignedEntities()
	if err != nil {
		return nil, err
	}
	signedRuntimes, err := rq.state.getSignedRuntimes()
	if err != nil {
		return nil, err
	}
	signedNodes, err := rq.state.getSignedNodes()
	if err != nil {
		return nil, err
	}

	// We only want to keep the nodes that are validators.
	validatorNodes := make([]*node.SignedNode, 0)
	for _, sn := range signedNodes {
		var n node.Node
		if err = cbor.Unmarshal(sn.Blob, &n); err != nil {
			return nil, err
		}

		if n.HasRoles(node.RoleValidator) {
			validatorNodes = append(validatorNodes, sn)
		}
	}

	gen := registry.Genesis{
		Entities:           signedEntities,
		Runtimes:           signedRuntimes,
		Nodes:              validatorNodes,
		KeyManagerOperator: rq.state.getKeyManagerOperator(),
	}
	return &gen, nil
}
