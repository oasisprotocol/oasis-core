package scheduler

import (
	"crypto"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/common/crypto/mathrand"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/genesis"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
	beaconapp "github.com/oasislabs/ekiden/go/tendermint/apps/beacon"
	registryapp "github.com/oasislabs/ekiden/go/tendermint/apps/registry"
)

var (
	_ abci.Application = (*schedulerApplication)(nil)

	rngContextCompute              = []byte("EkS-Dummy-Compute")
	rngContextStorage              = []byte("EkS-Dummy-Storage")
	rngContextTransactionScheduler = []byte("EkS-Dummy-TransactionScheduler")
)

type schedulerApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.BlockBackend
}

func (app *schedulerApplication) Name() string {
	return AppName
}

func (app *schedulerApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *schedulerApplication) Blessed() bool {
	return false
}

func (app *schedulerApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *schedulerApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register query handlers.
	queryRouter.AddRoute(QueryAllCommittees, nil, app.queryAllCommittees)
	queryRouter.AddRoute(QueryKindsCommittees, []scheduler.CommitteeKind{}, app.queryKindsCommittees)
}

func (app *schedulerApplication) OnCleanup() {}

func (app *schedulerApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *schedulerApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	return nil
}

func (app *schedulerApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *schedulerApplication) InitChain(ctx *abci.Context, req types.RequestInitChain, doc *genesis.Document) error {
	return nil
}

func (app *schedulerApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// TODO: We'll later have this for each type of committee.
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		app.logger.Debug("BeginBlock with epoch change %%%",
			"epoch", epoch,
		)

		beaconState := beaconapp.NewMutableState(app.state.DeliverTxTree())
		beacon, err := beaconState.GetBeacon(epoch)
		if err != nil {
			return fmt.Errorf("couldn't get beacon: %s", err.Error())
		}

		regState := registryapp.NewMutableState(app.state.DeliverTxTree())
		runtimes, err := regState.GetRuntimes()
		if err != nil {
			return fmt.Errorf("couldn't get runtimes: %s", err.Error())
		}
		nodes, err := regState.GetNodes()
		if err != nil {
			return fmt.Errorf("couldn't get nodes: %s", err.Error())
		}

		if err := app.electAll(ctx, request, epoch, beacon, runtimes, nodes, scheduler.Compute); err != nil {
			return fmt.Errorf("couldn't elect compute committees: %s", err.Error())
		}
		if err := app.electAll(ctx, request, epoch, beacon, runtimes, nodes, scheduler.Storage); err != nil {
			return fmt.Errorf("couldn't elect storage committees: %s", err.Error())
		}
		if err := app.electAll(ctx, request, epoch, beacon, runtimes, nodes, scheduler.TransactionScheduler); err != nil {
			return fmt.Errorf("couldn't elect transaction scheduler committees: %s", err.Error())
		}
		ctx.EmitTag(api.TagApplication, []byte(app.Name()))
		ctx.EmitTag(TagElected, cbor.Marshal([]scheduler.CommitteeKind{scheduler.Compute, scheduler.Storage, scheduler.TransactionScheduler}))
	}
	return nil
}

func (app *schedulerApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	return nil
}

func (app *schedulerApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *schedulerApplication) EndBlock(req types.RequestEndBlock) (types.ResponseEndBlock, error) {
	return types.ResponseEndBlock{}, nil
}

func (app *schedulerApplication) FireTimer(ctx *abci.Context, t *abci.Timer) {}

func (app *schedulerApplication) queryAllCommittees(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	committees, err := state.getAllCommittees()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(committees), nil
}

func (app *schedulerApplication) queryKindsCommittees(s interface{}, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	request := r.([]scheduler.CommitteeKind)
	committees, err := state.getKindsCommittees(request)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(committees), nil
}

func (app *schedulerApplication) isSuitableComputeWorker(n *node.Node, rt *registry.Runtime, ts time.Time) bool {
	if !n.HasRoles(node.RoleComputeWorker) {
		return false
	}
	for _, nrt := range n.Runtimes {
		if !nrt.ID.Equal(rt.ID) {
			continue
		}
		switch rt.TEEHardware {
		case node.TEEHardwareInvalid:
			if nrt.Capabilities.TEE != nil {
				return false
			}
			return true
		default:
			if nrt.Capabilities.TEE == nil {
				return false
			}
			if nrt.Capabilities.TEE.Hardware != rt.TEEHardware {
				return false
			}
			if err := nrt.Capabilities.TEE.Verify(ts); err != nil {
				app.logger.Warn("failed to verify node TEE attestaion",
					"err", err,
					"node", n,
					"time_stamp", ts,
					"runtime", rt.ID,
				)
				return false
			}
			return true
		}
	}
	return false
}

func (app *schedulerApplication) isSuitableStorageWorker(n *node.Node) bool {
	return n.HasRoles(node.RoleStorageWorker)
}

func (app *schedulerApplication) isSuitableTransactionScheduler(n *node.Node, rt *registry.Runtime) bool {
	if !n.HasRoles(node.RoleTransactionScheduler) {
		return false
	}
	for _, nrt := range n.Runtimes {
		if !nrt.ID.Equal(rt.ID) {
			continue
		}
		return true
	}
	return false
}

// Operates on consensus connection.
func (app *schedulerApplication) elect(ctx *abci.Context, request types.RequestBeginBlock, epoch epochtime.EpochTime, beacon []byte, rt *registry.Runtime, nodes []*node.Node, kind scheduler.CommitteeKind) error {
	// Only generic compute runtimes need to elect all the committees.
	if !rt.IsCompute() && kind != scheduler.Compute {
		return nil
	}

	var nodeList []*node.Node
	var sz int
	var rngCtx []byte
	switch kind {
	case scheduler.Compute:
		for _, n := range nodes {
			if app.isSuitableComputeWorker(n, rt, request.Header.Time) {
				nodeList = append(nodeList, n)
			}
		}
		sz = int(rt.ReplicaGroupSize + rt.ReplicaGroupBackupSize)
		rngCtx = rngContextCompute
	case scheduler.Storage:
		for _, n := range nodes {
			if app.isSuitableStorageWorker(n) {
				nodeList = append(nodeList, n)
			}
		}
		sz = int(rt.StorageGroupSize)
		rngCtx = rngContextStorage
	case scheduler.TransactionScheduler:
		for _, n := range nodes {
			if app.isSuitableTransactionScheduler(n, rt) {
				nodeList = append(nodeList, n)
			}
		}
		sz = int(rt.TransactionSchedulerGroupSize)
		rngCtx = rngContextTransactionScheduler
	default:
		return fmt.Errorf("scheduler: invalid committee type: %v", kind)
	}
	nrNodes := len(nodeList)

	if sz == 0 {
		return fmt.Errorf("scheduler: empty committee not allowed")
	}
	if sz > nrNodes {
		return fmt.Errorf("scheduler: %v committee size %d exceeds available nodes %d", kind, sz, nrNodes)
	}

	drbg, err := drbg.New(crypto.SHA512, beacon, rt.ID[:], rngCtx)
	if err != nil {
		return fmt.Errorf("scheduler: couldn't instantiate DRBG: %s", err.Error())
	}
	rngSrc := mathrand.New(drbg)
	rng := rand.New(rngSrc)

	var idxs []int
	// NOTE: We currently don't support replicated storage.
	// The storage client currently connects to the storage committee
	// leader and if it would change between epochs, things would go pretty
	// badly.
	// XXX: This only ensures the same storage node will be the leader if
	// the list of registered storage nodes doesn't change.
	if kind == scheduler.Storage {
		// Sort nodes by their public key.
		sort.Slice(nodeList, func(i, j int) bool { return nodeList[i].ID.String() < nodeList[j].ID.String() })
		// Set idxs to identity instead of a random permutation.
		idxs = make([]int, len(nodeList))
		for i := range idxs {
			idxs[i] = i
		}
	} else {
		idxs = rng.Perm(nrNodes)
	}

	var members []*scheduler.CommitteeNode

	for i := 0; i < sz; i++ {
		var role scheduler.Role
		switch {
		case i == 0:
			role = scheduler.Leader
		case i >= int(rt.ReplicaGroupSize):
			role = scheduler.BackupWorker
		default:
			role = scheduler.Worker
		}
		members = append(members, &scheduler.CommitteeNode{
			Role:      role,
			PublicKey: nodeList[idxs[i]].ID,
		})
	}

	newMutableState(app.state.DeliverTxTree()).putCommittee(kind, rt.ID, members)
	return nil
}

// Operates on consensus connection.
func (app *schedulerApplication) electAll(ctx *abci.Context, request types.RequestBeginBlock, epoch epochtime.EpochTime, beacon []byte, runtimes []*registry.Runtime, nodes []*node.Node, kind scheduler.CommitteeKind) error {
	for _, runtime := range runtimes {
		if err := app.elect(ctx, request, epoch, beacon, runtime, nodes, kind); err != nil {
			return err
		}
	}
	return nil
}

// New constructs a new scheduler application instance.
func New(
	timeSource epochtime.BlockBackend,
) abci.Application {
	return &schedulerApplication{
		logger:     logging.GetLogger("tendermint/scheduler"),
		timeSource: timeSource,
	}
}
