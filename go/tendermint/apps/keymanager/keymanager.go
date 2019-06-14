package keymanager

import (
	"bytes"
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/genesis"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
)

type keymanagerApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.BlockBackend
}

func (app *keymanagerApplication) Name() string {
	return AppName
}

func (app *keymanagerApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *keymanagerApplication) Blessed() bool {
	return false
}

func (app *keymanagerApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *keymanagerApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryGetStatus, tmapi.QueryGetByIDRequest{}, app.queryGetStatus)
	queryRouter.AddRoute(QueryGetStatuses, nil, app.queryGetStatuses)
}

func (app *keymanagerApplication) OnCleanup() {}

func (app *keymanagerApplication) SetOption(request types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *keymanagerApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	// TODO: Add policy support.
	return errors.New("tendermint/keymanager: transactions not supported yet")
}

func (app *keymanagerApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *keymanagerApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	// TODO: Implement support for this, once it is sensible to do so.
	// Note: Registry app needs to be moved above the keymanager one.
	return nil
}

func (app *keymanagerApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		return app.onEpochChange(ctx, epoch)
	}
	return nil
}

func (app *keymanagerApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	// TODO: Add policy support.
	return errors.New("tendermint/keymanager: transactions not supported yet")
}

func (app *keymanagerApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *keymanagerApplication) EndBlock(request types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *keymanagerApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) {}

func (app *keymanagerApplication) queryGetStatus(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	request := r.(*tmapi.QueryGetByIDRequest)

	status, err := state.GetStatus(request.ID)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(status), nil
}

func (app *keymanagerApplication) queryGetStatuses(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)

	statuses, err := state.GetStatuses()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(statuses), nil
}

func (app *keymanagerApplication) onEpochChange(ctx *abci.Context, epoch epochtime.EpochTime) error {
	tree := app.state.DeliverTxTree()

	// Query the runtime and node lists.
	regState := registryapp.NewMutableState(tree)
	runtimes, _ := regState.GetRuntimes()
	nodes, _ := regState.GetNodes()
	registry.SortNodeList(nodes)

	// Recalculate all the key manager statuses.
	//
	// Note: This assumes that once a runtime is registered, it never expires.
	var toEmit []*api.Status
	state := NewMutableState(app.state.DeliverTxTree())
	for _, rt := range runtimes {
		if rt.Kind != registry.KindKeyManager {
			continue
		}

		var forceEmit bool
		oldStatus, err := state.GetStatus(rt.ID)
		if err != nil {
			// This is fatal, as it suggests state corruption.
			app.logger.Error("failed to query key manager status",
				"id", rt.ID,
				"err", err,
			)
			return errors.Wrap(err, "failed to query key manager status")
		}
		if oldStatus == nil {
			// This must be a new key manager runtime.
			forceEmit = true
			oldStatus = &api.Status{
				ID: rt.ID,
			}
		}

		newStatus := app.generateStatus(rt, oldStatus, nodes)
		if forceEmit || !bytes.Equal(cbor.Marshal(oldStatus), cbor.Marshal(newStatus)) {
			app.logger.Debug("status updated",
				"id", newStatus.ID,
				"is_initialized", newStatus.IsInitialized,
				"is_secure", newStatus.IsSecure,
				"checksum", hex.EncodeToString(newStatus.Checksum),
				"nodes", newStatus.Nodes,
			)

			// Set, enqueue for emit.
			state.setStatus(newStatus)
			toEmit = append(toEmit, newStatus)
		}
	}

	// Emit the update event if required.
	if len(toEmit) > 0 {
		ctx.EmitTag(tmapi.TagApplication, []byte(app.Name()))
		ctx.EmitTag(TagStatusUpdate, cbor.Marshal(toEmit))
	}

	return nil
}

func (app *keymanagerApplication) generateStatus(kmrt *registry.Runtime, oldStatus *api.Status, nodes []*node.Node) *api.Status {
	status := &api.Status{
		ID:            kmrt.ID,
		IsInitialized: oldStatus.IsInitialized,
		IsSecure:      oldStatus.IsSecure,
		Checksum:      oldStatus.Checksum,
	}

	for _, n := range nodes {
		if !n.HasRoles(node.RoleKeyManager) {
			continue
		}

		var nodeRt *node.Runtime
		for _, rt := range n.Runtimes {
			if rt.ID.Equal(kmrt.ID) {
				nodeRt = rt
				break
			}
		}
		if nodeRt == nil {
			continue
		}

		initResponse, err := api.VerifyExtraInfo(kmrt, nodeRt)
		if err != nil {
			app.logger.Error("failed to validate ExtraInfo",
				"err", err,
				"id", kmrt.ID,
				"node_id", n.ID,
			)
			continue
		}

		if status.IsInitialized {
			// Already initialized.  Check to see if it should be added to
			// the node list.
			if initResponse.IsSecure != status.IsSecure {
				app.logger.Error("Security status mismatch for runtime",
					"id", kmrt.ID,
					"node_id", n.ID,
				)
				continue
			}
			if !bytes.Equal(initResponse.Checksum, status.Checksum) {
				app.logger.Error("Checksum mismatch for runtime",
					"id", kmrt.ID,
					"node_id", n.ID,
				)
				continue
			}
		} else {
			// Not initialized.  The first node gets to be the source
			// of truth, every other node will sync off it.

			// TODO: Sanity check IsSecure/Checksum.
			status.IsSecure = initResponse.IsSecure
			status.IsInitialized = true
			status.Checksum = initResponse.Checksum
		}

		status.Nodes = append(status.Nodes, n.ID)
	}

	return status
}

func New(timeSource epochtime.BlockBackend) abci.Application {
	return &keymanagerApplication{
		logger:     logging.GetLogger("tendermint/keymanager"),
		timeSource: timeSource,
	}
}
