package scheduler

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/drbg"
	"github.com/oasislabs/oasis-core/go/common/crypto/mathrand"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
	beaconapp "github.com/oasislabs/oasis-core/go/tendermint/apps/beacon"
	registryapp "github.com/oasislabs/oasis-core/go/tendermint/apps/registry"
	stakingapp "github.com/oasislabs/oasis-core/go/tendermint/apps/staking"
)

var (
	_ abci.Application = (*schedulerApplication)(nil)

	rngContextCompute              = []byte("EkS-ABCI-Compute")
	rngContextStorage              = []byte("EkS-ABCI-Storage")
	rngContextTransactionScheduler = []byte("EkS-ABCI-TransactionScheduler")
	rngContextMerge                = []byte("EkS-ABCI-Merge")
	rngContextValidators           = []byte("EkS-ABCI-Validators")

	errUnexpectedTransaction = errors.New("tendermint/scheduler: unexpected transaction")
)

type stakeAccumulator struct {
	stakeCache     *stakingapp.StakeCache
	perEntityStake map[signature.MapKey][]staking.ThresholdKind

	unsafeBypass bool
}

func (acc *stakeAccumulator) checkThreshold(id signature.PublicKey, kind staking.ThresholdKind, accumulate bool) error {
	if acc.unsafeBypass {
		return nil
	}

	mk := id.ToMapKey()

	// The staking balance is per-entity.  Each entity can have multiple nodes,
	// that each can serve multiple roles.  Check the entity's balance to see
	// that it has sufficient stake for the current roles and the additional
	// role.
	kinds := make([]staking.ThresholdKind, 0, 1)
	if existing, ok := acc.perEntityStake[mk]; ok && len(existing) > 0 {
		kinds = append(kinds, existing...)
	}
	kinds = append(kinds, kind)

	if err := acc.stakeCache.EnsureSufficientStake(id, kinds); err != nil {
		return err
	}

	if accumulate {
		// The entity has sufficient stake to qualify for the additional role,
		// update the accumulated roles.
		acc.perEntityStake[mk] = kinds
	}

	return nil
}

func newStakeAccumulator(ctx *abci.Context, unsafeBypass bool) (*stakeAccumulator, error) {
	stakeCache, err := stakingapp.NewStakeCache(ctx)
	if err != nil {
		return nil, err
	}

	return &stakeAccumulator{
		stakeCache:     stakeCache,
		perEntityStake: make(map[signature.MapKey][]staking.ThresholdKind),
		unsafeBypass:   unsafeBypass,
	}, nil
}

type schedulerApplication struct {
	logger *logging.Logger
	state  *abci.ApplicationState

	timeSource epochtime.Backend

	cfg *scheduler.Config

	baseEpoch epochtime.EpochTime
}

func (app *schedulerApplication) Name() string {
	return AppName
}

func (app *schedulerApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *schedulerApplication) Blessed() bool {
	return true
}

func (app *schedulerApplication) Dependencies() []string {
	return []string{beaconapp.AppName, registryapp.AppName, stakingapp.AppName}
}

func (app *schedulerApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *schedulerApplication) OnRegister(state *abci.ApplicationState) {
	app.state = state
}

func (app *schedulerApplication) OnCleanup() {}

func (app *schedulerApplication) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *schedulerApplication) InitChain(ctx *abci.Context, req types.RequestInitChain, doc *genesis.Document) error {
	if app.cfg.DebugStaticValidators {
		app.logger.Warn("static validators are configured")
		return nil
	}

	regState := registryapp.NewMutableState(app.state.DeliverTxTree())
	nodes, err := regState.GetNodes()
	if err != nil {
		return errors.Wrap(err, "tendermint/scheduler: couldn't get nodes")
	}

	registeredValidators := make(map[signature.MapKey]*node.Node)
	for _, v := range nodes {
		if v.HasRoles(node.RoleValidator) {
			registeredValidators[v.ID.ToMapKey()] = v
		}
	}

	// Assemble the list of the tendermint genesis validators, and do some
	// sanity checking.
	var currentValidators []signature.PublicKey
	for _, v := range req.Validators {
		tmPk := v.GetPubKey()

		if t := tmPk.GetType(); t != types.PubKeyEd25519 {
			app.logger.Error("invalid genesis validator public key type",
				"public_key", hex.EncodeToString(tmPk.GetData()),
				"type", t,
			)
			return fmt.Errorf("scheduler: invalid genesus validator public key type: '%v'", t)
		}

		var id signature.PublicKey
		if err = id.UnmarshalBinary(tmPk.GetData()); err != nil {
			app.logger.Error("invalid genesis validator public key",
				"err", err,
				"public_key", hex.EncodeToString(tmPk.GetData()),
			)
			return errors.Wrap(err, "scheduler: invalid genesis validator public key")
		}

		if power := v.GetPower(); power != api.VotingPower {
			app.logger.Error("invalid voting power",
				"id", id,
				"power", power,
			)
			return fmt.Errorf("scheduler: invalid genesis validator voting power: %v", power)
		}

		n := registeredValidators[id.ToMapKey()]
		if n == nil {
			app.logger.Error("genesis validator not in registry",
				"id", id,
			)
			return fmt.Errorf("scheduler: genesis validator not in registry")
		}
		app.logger.Debug("adding validator to current validator set",
			"id", id,
		)
		currentValidators = append(currentValidators, n.ID)
	}

	// TODO/security: Enforce genesis validator staking.

	// Add the current validator set to ABCI, so that we can alter it later.
	//
	// Sort of stupid it needs to be done this way, but tendermint doesn't
	// appear to pass ABCI the validator set anywhere other than InitChain.

	state := NewMutableState(app.state.DeliverTxTree())
	state.putCurrentValidators(currentValidators)

	return nil
}

func (app *schedulerApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) error {
	// TODO: We'll later have this for each type of committee.
	if changed, epoch := app.state.EpochChanged(app.timeSource); changed {
		// The 0th epoch will not have suitable entropy for elections, nor
		// will it have useful node registrations.
		if epoch == app.baseEpoch {
			app.logger.Info("system in bootstrap period, skipping election",
				"epoch", epoch,
			)
			return nil
		}

		beaconState := beaconapp.NewMutableState(app.state.DeliverTxTree())
		beacon, err := beaconState.GetBeacon()
		if err != nil {
			return errors.Wrap(err, "tendermint/scheduler: couldn't get beacon")
		}

		regState := registryapp.NewMutableState(app.state.DeliverTxTree())
		runtimes, err := regState.GetRuntimes()
		if err != nil {
			return errors.Wrap(err, "tendermint/scheduler: couldn't get runtimes")
		}
		nodes, err := regState.GetNodes()
		if err != nil {
			return errors.Wrap(err, "tendermint/scheduler: couldn't get nodes")
		}

		entityStake, err := newStakeAccumulator(ctx, app.cfg.DebugBypassStake)
		if err != nil {
			return errors.Wrap(err, "tendermint/scheduler: couldn't get stake snapshot")
		}

		// Handle the validator election first, because no consensus is
		// catastrophic, while no validators is not.
		if !app.cfg.DebugStaticValidators {
			if err = app.electValidators(ctx, beacon, entityStake, nodes); err != nil {
				// It is unclear what the behavior should be if the validator
				// election fails.  The system can not ensure integrity, so
				// presumably manual intervention is required...
				return errors.Wrap(err, "tendermint/scheduler: couldn't elect validators")
			}
		}

		kinds := []scheduler.CommitteeKind{scheduler.KindCompute, scheduler.KindStorage, scheduler.KindTransactionScheduler, scheduler.KindMerge}
		for _, kind := range kinds {
			if err = app.electAllCommittees(ctx, request, epoch, beacon, entityStake, runtimes, nodes, kind); err != nil {
				return errors.Wrap(err, fmt.Sprintf("tendermint/scheduler: couldn't elect %s committees", kind))
			}
		}
		ctx.EmitTag([]byte(app.Name()), api.TagAppNameValue)
		ctx.EmitTag(TagElected, cbor.Marshal(kinds))

		var kindNames []string
		for _, kind := range kinds {
			kindNames = append(kindNames, kind.String())
		}
		var runtimeIDs []string
		for _, rt := range runtimes {
			runtimeIDs = append(runtimeIDs, rt.ID.String())
		}
		app.logger.Debug("finished electing committees",
			"epoch", epoch,
			"kinds", kindNames,
			"runtimes", runtimeIDs,
		)
	}
	return nil
}

func (app *schedulerApplication) ExecuteTx(ctx *abci.Context, tx []byte) error {
	return errUnexpectedTransaction
}

func (app *schedulerApplication) ForeignExecuteTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *schedulerApplication) EndBlock(ctx *abci.Context, req types.RequestEndBlock) (types.ResponseEndBlock, error) {
	var resp types.ResponseEndBlock

	state := NewMutableState(app.state.DeliverTxTree())
	pendingValidators, err := state.getPendingValidators()
	if err != nil {
		return resp, errors.Wrap(err, "scheduler/tendermint: failed to query pending validators")
	}
	if pendingValidators == nil {
		// No validator updates to apply.
		return resp, nil
	}

	currentValidators, err := state.getCurrentValidators()
	if err != nil {
		return resp, errors.Wrap(err, "scheduler/tendermint: failed to query current validators")
	}

	// Clear out the pending validator update.
	state.putPendingValidators(nil)

	// Tendermint expects a vector of ValidatorUpdate that expresses
	// the difference between the current validator set (tracked manually
	// from InitChain), and the new validator set, which is a huge pain
	// in the ass.

	currentMap := make(map[signature.MapKey]bool)
	for _, v := range currentValidators {
		currentMap[v.ToMapKey()] = true
	}

	pendingMap := make(map[signature.MapKey]bool)
	for _, v := range pendingValidators {
		pendingMap[v.ToMapKey()] = true
	}

	var updates []types.ValidatorUpdate
	for _, v := range currentValidators {
		mk := v.ToMapKey()

		switch pendingMap[mk] {
		case false:
			// Existing validator is not part of the new set, reduce it's
			// voting power to 0, to indicate removal.
			app.logger.Debug("removing existing validator from validator set",
				"id", v,
			)
			updates = append(updates, api.PublicKeyToValidatorUpdate(v, 0))
		case true:
			// Existing validator is part of the new set, remove it from
			// the pending map, since there is nothing to be done.
			pendingMap[mk] = false
		}
	}

	for _, v := range pendingValidators {
		mk := v.ToMapKey()

		if pendingMap[mk] {
			// This is a validator that is not part of the current set.
			app.logger.Debug("adding new validator to validator set",
				"id", v,
			)
			updates = append(updates, api.PublicKeyToValidatorUpdate(v, api.VotingPower))
		} else {
			app.logger.Debug("keeping existing validator in the validator set",
				"id", v,
			)
		}
	}

	resp.ValidatorUpdates = updates

	// Stash the updated validator set.
	state.putCurrentValidators(pendingValidators)

	return resp, nil
}

func (app *schedulerApplication) FireTimer(ctx *abci.Context, t *abci.Timer) error {
	return errors.New("tendermint/scheduler: unexpected timer")
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

func (app *schedulerApplication) isSuitableStorageWorker(n *node.Node, rt *registry.Runtime, ts time.Time) bool {
	return n.HasRoles(node.RoleStorageWorker)
}

func (app *schedulerApplication) isSuitableTransactionScheduler(n *node.Node, rt *registry.Runtime, ts time.Time) bool {
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

func (app *schedulerApplication) isSuitableMergeWorker(n *node.Node, rt *registry.Runtime, ts time.Time) bool {
	if !n.HasRoles(node.RoleMergeWorker) {
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
// Return error if node should crash.
// For non-fatal problems, save a problem condition to the state and return successfully.
func (app *schedulerApplication) electCommittee(ctx *abci.Context, request types.RequestBeginBlock, epoch epochtime.EpochTime, beacon []byte, entityStake *stakeAccumulator, rt *registry.Runtime, nodes []*node.Node, kind scheduler.CommitteeKind) error {
	// Only generic compute runtimes need to elect all the committees.
	if !rt.IsCompute() && kind != scheduler.KindCompute {
		return nil
	}

	// Determine the context, committee size, and pre-filter the node-list
	// based on eligibility and entity stake.
	var (
		nodeList []*node.Node

		rngCtx       []byte
		threshold    staking.ThresholdKind
		isSuitableFn func(*node.Node, *registry.Runtime, time.Time) bool

		workerSize, backupSize int
	)

	switch kind {
	case scheduler.KindCompute:
		rngCtx = rngContextCompute
		threshold = staking.KindCompute
		isSuitableFn = app.isSuitableComputeWorker
		workerSize = int(rt.ReplicaGroupSize)
		backupSize = int(rt.ReplicaGroupBackupSize)
	case scheduler.KindStorage:
		rngCtx = rngContextStorage
		threshold = staking.KindStorage
		isSuitableFn = app.isSuitableStorageWorker
		workerSize = int(rt.StorageGroupSize)
	case scheduler.KindTransactionScheduler:
		rngCtx = rngContextTransactionScheduler
		threshold = staking.KindCompute
		isSuitableFn = app.isSuitableTransactionScheduler
		workerSize = int(rt.TransactionSchedulerGroupSize)
	case scheduler.KindMerge:
		rngCtx = rngContextMerge
		threshold = staking.KindCompute
		isSuitableFn = app.isSuitableMergeWorker
		// TODO: Allow independent group sizes.
		workerSize = int(rt.ReplicaGroupSize)
		backupSize = int(rt.ReplicaGroupBackupSize)
	default:
		return fmt.Errorf("tendermint/scheduler: invalid committee type: %v", kind)
	}

	for _, n := range nodes {
		// Check, but do not accumulate stake till the election happens.
		if err := entityStake.checkThreshold(n.EntityID, threshold, false); err != nil {
			continue
		}
		if isSuitableFn(n, rt, request.Header.Time) {
			nodeList = append(nodeList, n)
		}
	}

	// Ensure that it is theoretically possible to elect a valid committee.
	if workerSize == 0 {
		app.logger.Error("empty committee not allowed",
			"kind", kind,
			"runtime_id", rt.ID,
		)
		NewMutableState(app.state.DeliverTxTree()).dropCommittee(kind, rt.ID)
		return nil
	}

	nrNodes, wantedNodes := len(nodeList), workerSize+backupSize
	if wantedNodes > nrNodes {
		app.logger.Error("committee size exceeds available nodes (pre-stake)",
			"kind", kind,
			"runtime_id", rt.ID,
			"worker_size", workerSize,
			"backup_size", backupSize,
			"nr_nodes", nrNodes,
		)
		NewMutableState(app.state.DeliverTxTree()).dropCommittee(kind, rt.ID)
		return nil
	}

	// Do the actual election.
	drbg, err := drbg.New(crypto.SHA512, beacon, rt.ID[:], rngCtx)
	if err != nil {
		return errors.Wrap(err, "tendermint/scheduler: couldn't instantiate DRBG")
	}
	rng := rand.New(mathrand.New(drbg))
	idxs := rng.Perm(nrNodes)

	var members []*scheduler.CommitteeNode
	for i := 0; i < len(idxs); i++ {
		n := nodeList[idxs[i]]

		// Re-check and then accumulate the entity's stake.
		if err = entityStake.checkThreshold(n.EntityID, threshold, true); err != nil {
			continue
		}

		role := scheduler.Worker
		if i == 0 && kind.NeedsLeader() {
			role = scheduler.Leader
		} else if i >= workerSize {
			role = scheduler.BackupWorker
		}
		members = append(members, &scheduler.CommitteeNode{
			Role:      role,
			PublicKey: nodeList[idxs[i]].ID,
		})
		if len(members) >= wantedNodes {
			break
		}
	}

	if len(members) != wantedNodes {
		app.logger.Error("insufficent nodes with adequate stake to elect",
			"kind", kind,
			"runtime_id", rt.ID,
			"worker_size", workerSize,
			"backup_size", backupSize,
			"available", len(members),
		)
		NewMutableState(app.state.DeliverTxTree()).dropCommittee(kind, rt.ID)
		return nil
	}

	NewMutableState(app.state.DeliverTxTree()).putCommittee(&scheduler.Committee{
		Kind:      kind,
		RuntimeID: rt.ID,
		Members:   members,
		ValidFor:  epoch,
	})
	return nil
}

// Operates on consensus connection.
func (app *schedulerApplication) electAllCommittees(ctx *abci.Context, request types.RequestBeginBlock, epoch epochtime.EpochTime, beacon []byte, entityStake *stakeAccumulator, runtimes []*registry.Runtime, nodes []*node.Node, kind scheduler.CommitteeKind) error {
	for _, runtime := range runtimes {
		if err := app.electCommittee(ctx, request, epoch, beacon, entityStake, runtime, nodes, kind); err != nil {
			return err
		}
	}
	return nil
}

func (app *schedulerApplication) electValidators(ctx *abci.Context, beacon []byte, entityStake *stakeAccumulator, nodes []*node.Node) error {
	// XXX: How many validators do we want, anyway?
	const maxValidators = 100

	// Filter the node list based on eligibility and entity stake.
	var nodeList []*node.Node
	for _, n := range nodes {
		if !n.HasRoles(node.RoleValidator) {
			continue
		}
		if err := entityStake.checkThreshold(n.EntityID, staking.KindValidator, false); err != nil {
			continue
		}
		nodeList = append(nodeList, n)
	}

	drbg, err := drbg.New(crypto.SHA512, beacon, nil, rngContextValidators)
	if err != nil {
		return errors.Wrap(err, "tendermint/scheduler: couldn't instantiate DRBG")
	}
	rngSrc := mathrand.New(drbg)
	rng := rand.New(rngSrc)

	// Generate the permutation assuming the entire eligible node list may
	// need to be traversed, due to some nodes having insufficient stake.
	idxs := rng.Perm(len(nodeList))

	var newValidators []signature.PublicKey
	for i := 0; i < len(idxs); i++ {
		n := nodeList[idxs[i]]

		// Re-check and then accumulate the entity's stake.
		if err = entityStake.checkThreshold(n.EntityID, staking.KindValidator, true); err != nil {
			continue
		}

		newValidators = append(newValidators, n.ID)
		if len(newValidators) >= maxValidators {
			break
		}
	}

	if len(newValidators) == 0 {
		return fmt.Errorf("tendermint/scheduler: failed to elect any validators")
	}

	// Set the new pending validator set in the ABCI state.  It needs to be
	// applied in EndBlock.
	state := NewMutableState(app.state.DeliverTxTree())
	state.putPendingValidators(newValidators)

	return nil
}

// New constructs a new scheduler application instance.
func New(
	timeSource epochtime.Backend,
	cfg *scheduler.Config,
) (abci.Application, error) {
	baseEpoch, err := timeSource.GetBaseEpoch(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "tendermint/scheduler: couldn't query base epoch")
	}

	return &schedulerApplication{
		logger:     logging.GetLogger("tendermint/scheduler"),
		timeSource: timeSource,
		cfg:        cfg,
		baseEpoch:  baseEpoch,
	}, nil
}
