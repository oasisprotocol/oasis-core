package secrets

import (
	"bytes"
	"encoding/hex"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func (ext *secretsExt) onEpochChange(ctx *tmapi.Context, epoch beacon.EpochTime) error {
	// Query the runtime and node lists.
	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes(ctx)
	nodes, _ := regState.Nodes(ctx)
	registry.SortNodeList(nodes)

	params, err := regState.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get consensus parameters: %w", err)
	}

	// Recalculate all the key manager statuses.
	//
	// Note: This assumes that once a runtime is registered, it never expires.
	var toEmit []*secrets.Status
	state := secretsState.NewMutableState(ctx.State())
	for _, rt := range runtimes {
		if rt.Kind != registry.KindKeyManager {
			continue
		}

		var forceEmit bool
		oldStatus, err := state.Status(ctx, rt.ID)
		switch err {
		case nil:
		case secrets.ErrNoSuchStatus:
			// This must be a new key manager runtime.
			forceEmit = true
			oldStatus = &secrets.Status{
				ID: rt.ID,
			}
		default:
			// This is fatal, as it suggests state corruption.
			ctx.Logger().Error("failed to query key manager status",
				"id", rt.ID,
				"err", err,
			)
			return fmt.Errorf("failed to query key manager status: %w", err)
		}

		secret, err := state.MasterSecret(ctx, rt.ID)
		if err != nil && err != secrets.ErrNoSuchMasterSecret {
			ctx.Logger().Error("failed to query key manager master secret",
				"id", rt.ID,
				"err", err,
			)
			return fmt.Errorf("failed to query key manager master secret: %w", err)
		}

		newStatus := generateStatus(ctx, rt, oldStatus, secret, nodes, params, epoch)
		if forceEmit || !bytes.Equal(cbor.Marshal(oldStatus), cbor.Marshal(newStatus)) {
			ctx.Logger().Debug("status updated",
				"id", newStatus.ID,
				"is_initialized", newStatus.IsInitialized,
				"is_secure", newStatus.IsSecure,
				"generation", newStatus.Generation,
				"rotation_epoch", newStatus.RotationEpoch,
				"checksum", hex.EncodeToString(newStatus.Checksum),
				"rsk", newStatus.RSK,
				"nodes", newStatus.Nodes,
			)

			// Set, enqueue for emit.
			if err = state.SetStatus(ctx, newStatus); err != nil {
				return fmt.Errorf("failed to set key manager status: %w", err)
			}
			toEmit = append(toEmit, newStatus)
		}
	}

	// Note: It may be a good idea to sweep statuses that don't have runtimes,
	// but as runtime registrations last forever, so this shouldn't be possible.

	// Emit the update event if required.
	if len(toEmit) > 0 {
		ctx.EmitEvent(tmapi.NewEventBuilder(ext.appName).TypedAttribute(&secrets.StatusUpdateEvent{
			Statuses: toEmit,
		}))
	}

	return nil
}
