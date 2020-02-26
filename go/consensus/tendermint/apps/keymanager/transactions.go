package keymanager

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	tmapi "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	keymanagerState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/keymanager/state"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

func (app *keymanagerApplication) updatePolicy(
	ctx *abci.Context,
	state *keymanagerState.MutableState,
	sigPol *api.SignedPolicySGX,
) error {
	// Ensure that the runtime exists and is a key manager.
	regState := registryState.NewMutableState(ctx.State())
	rt, err := regState.Runtime(sigPol.Policy.ID)
	if err != nil {
		return err
	}
	if rt.Kind != registry.KindKeyManager {
		return fmt.Errorf("keymanager: runtime is not a key manager: %s", sigPol.Policy.ID)
	}

	// Ensure that the tx signer is the key manager owner.
	if !rt.EntityID.Equal(ctx.TxSigner()) {
		return fmt.Errorf("keymanager: invalid update signer: %s", sigPol.Policy.ID)
	}

	// Get the existing policy document, if one exists.
	oldStatus, err := state.Status(rt.ID)
	if err != nil {
		return err
	}

	// Validate the tx.
	if err = api.SanityCheckSignedPolicySGX(oldStatus.Policy, sigPol); err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this operation.
	regParams, err := regState.ConsensusParameters()
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, registry.GasOpUpdateKeyManager, regParams.GasCosts); err != nil {
		return err
	}

	// Ok, as far as we can tell the new policy is valid, apply it.
	//
	// Note: The key manager cohort responsible for servicing this ID
	// will be unresponsive for a minimum of one epoch as a new cohort
	// will only be formed on the epoch transition.  If replication
	// is in the picture, the replication process will take an
	// additional epoch.
	//
	// TODO: It would be possible to update the cohort on each
	// node-reregistration, but I'm not sure how often the policy
	// will get updated.
	nodes, _ := regState.Nodes()
	registry.SortNodeList(nodes)
	newStatus := app.generateStatus(ctx, rt, oldStatus, nodes)
	state.SetStatus(newStatus)

	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).Attribute(KeyStatusUpdate, cbor.Marshal([]*api.Status{newStatus})))

	return nil
}
