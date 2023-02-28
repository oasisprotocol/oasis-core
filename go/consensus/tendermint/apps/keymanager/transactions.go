package keymanager

import (
	"fmt"

	"golang.org/x/exp/slices"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	keymanagerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/keymanager/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func (app *keymanagerApplication) updatePolicy(
	ctx *tmapi.Context,
	state *keymanagerState.MutableState,
	sigPol *api.SignedPolicySGX,
) error {
	// Ensure that the runtime exists and is a key manager.
	regState := registryState.NewMutableState(ctx.State())
	rt, err := regState.Runtime(ctx, sigPol.Policy.ID)
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
	oldStatus, err := state.Status(ctx, rt.ID)
	switch err {
	case nil:
	case api.ErrNoSuchStatus:
		// This must be a new key manager runtime.
		oldStatus = &api.Status{
			ID: rt.ID,
		}
	default:
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
	kmParams, err := state.ConsensusParameters(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, api.GasOpUpdatePolicy, kmParams.GasCosts); err != nil {
		return err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil
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
	epoch, err := app.state.GetCurrentEpoch(ctx)
	if err != nil {
		return err
	}

	regParams, err := regState.ConsensusParameters(ctx)
	if err != nil {
		return err
	}

	nodes, _ := regState.Nodes(ctx)
	registry.SortNodeList(nodes)
	oldStatus.Policy = sigPol
	newStatus := app.generateStatus(ctx, rt, oldStatus, nodes, regParams, epoch)
	if err := state.SetStatus(ctx, newStatus); err != nil {
		ctx.Logger().Error("keymanager: failed to set key manager status",
			"err", err,
		)
		return fmt.Errorf("keymanager: failed to set key manager status: %w", err)
	}

	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).TypedAttribute(&api.StatusUpdateEvent{
		Statuses: []*api.Status{newStatus},
	}))

	return nil
}

func (app *keymanagerApplication) publishEphemeralSecret(
	ctx *tmapi.Context,
	state *keymanagerState.MutableState,
	secret *api.SignedEncryptedEphemeralSecret,
) error {
	// Ensure that the runtime exists and is a key manager.
	regState := registryState.NewMutableState(ctx.State())
	kmRt, err := regState.Runtime(ctx, secret.Secret.ID)
	if err != nil {
		return err
	}
	if kmRt.Kind != registry.KindKeyManager {
		return fmt.Errorf("keymanager: runtime is not a key manager: %s", secret.Secret.ID)
	}

	// Reject if the secret has been published.
	_, err = state.EphemeralSecret(ctx, secret.Secret.ID, secret.Secret.Epoch)
	switch err {
	case nil:
		return fmt.Errorf("keymanager: ephemeral secret for epoch %d already published", secret.Secret.Epoch)
	case api.ErrNoSuchEphemeralSecret:
		// Secret hasn't been published.
	default:
		return err
	}

	// Reject if the signer is not in the key manager committee.
	signer := ctx.TxSigner()
	kmStatus, err := state.Status(ctx, kmRt.ID)
	if err != nil {
		return err
	}
	if !slices.Contains(kmStatus.Nodes, signer) {
		return fmt.Errorf("keymanager: ephemeral secret can be published only by the key manager committee")
	}

	// Ensure that the signer is a key manager.
	n, err := regState.Node(ctx, signer)
	if err != nil {
		return err
	}
	idx := slices.IndexFunc(n.Runtimes, func(rt *node.Runtime) bool {
		// Skipping version check as key managers are running exactly one
		// version of the runtime.
		return rt.ID == kmRt.ID
	})
	if idx == -1 {
		return fmt.Errorf("keymanager: node is not a key manager")
	}
	nRt := n.Runtimes[idx]

	// Fetch RAK. Remember that registration ensures that node's hardware meets
	// the TEE requirements of the key manager runtime.
	var rak *signature.PublicKey
	switch kmRt.TEEHardware {
	case node.TEEHardwareInvalid:
		rak = &api.InsecureRAK
	case node.TEEHardwareIntelSGX:
		if nRt.Capabilities.TEE == nil {
			return fmt.Errorf("keymanager: node doesn't have TEE capability")
		}
		rak = &nRt.Capabilities.TEE.RAK
	default:
		return fmt.Errorf("keymanager: TEE hardware mismatch")
	}

	// Fetch REKs of the key manager committee.
	reks := make(map[x25519.PublicKey]struct{})
	for _, id := range kmStatus.Nodes {
		n, err = regState.Node(ctx, id)
		switch err {
		case nil:
		case registry.ErrNoSuchNode:
			continue
		default:
			return err
		}

		idx := slices.IndexFunc(n.Runtimes, func(rt *node.Runtime) bool {
			// Skipping version check as key managers are running exactly one
			// version of the runtime.
			return rt.ID == kmRt.ID
		})
		if idx == -1 {
			continue
		}
		nRt := n.Runtimes[idx]

		var rek x25519.PublicKey
		switch kmRt.TEEHardware {
		case node.TEEHardwareInvalid:
			rek = api.InsecureREK
		case node.TEEHardwareIntelSGX:
			if nRt.Capabilities.TEE == nil || nRt.Capabilities.TEE.REK == nil {
				continue
			}
			rek = *nRt.Capabilities.TEE.REK
		default:
			// Dead code (handled above).
		}

		reks[rek] = struct{}{}
	}

	// Verify the secret. Ephemeral secrets can be published for the next epoch only.
	epoch, err := app.state.GetCurrentEpoch(ctx)
	if err != nil {
		return err
	}
	if err = secret.Verify(epoch+1, reks, rak); err != nil {
		return err
	}

	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this operation.
	kmParams, err := state.ConsensusParameters(ctx)
	if err != nil {
		return err
	}
	if err = ctx.Gas().UseGas(1, api.GasOpPublishEphemeralSecret, kmParams.GasCosts); err != nil {
		return err
	}

	// Return early if simulating since this is just estimating gas.
	if ctx.IsSimulation() {
		return nil
	}

	// Ok, as far as we can tell the secret is valid, save it.
	if err := state.SetEphemeralSecret(ctx, secret); err != nil {
		ctx.Logger().Error("keymanager: failed to set key manager ephemeral secret",
			"err", err,
		)
		return fmt.Errorf("keymanager: failed to set key manager ephemeral secret: %w", err)
	}

	ctx.EmitEvent(tmapi.NewEventBuilder(app.Name()).TypedAttribute(&api.EphemeralSecretPublishedEvent{
		Secret: secret,
	}))

	return nil
}
