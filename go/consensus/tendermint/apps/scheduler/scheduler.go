package scheduler

import (
	"bytes"
	"crypto"
	"fmt"
	"math/rand"
	"sort"

	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	registryapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	_ api.Application = (*schedulerApplication)(nil)

	RNGContextExecutor   = []byte("EkS-ABCI-Compute")
	RNGContextValidators = []byte("EkS-ABCI-Validators")
	RNGContextEntities   = []byte("EkS-ABCI-Entities")

	RNGContextRoleWorker       = []byte("Worker")
	RNGContextRoleBackupWorker = []byte("Backup-Worker")
)

type schedulerApplication struct {
	state api.ApplicationState
}

func (app *schedulerApplication) Name() string {
	return AppName
}

func (app *schedulerApplication) ID() uint8 {
	return AppID
}

func (app *schedulerApplication) Methods() []transaction.MethodName {
	return nil
}

func (app *schedulerApplication) Blessed() bool {
	return true
}

func (app *schedulerApplication) Dependencies() []string {
	return []string{beaconapp.AppName, registryapp.AppName, stakingapp.AppName}
}

func (app *schedulerApplication) OnRegister(state api.ApplicationState, md api.MessageDispatcher) {
	app.state = state
}

func (app *schedulerApplication) OnCleanup() {}

func (app *schedulerApplication) BeginBlock(ctx *api.Context, request types.RequestBeginBlock) error {
	// Check if any stake slashing has occurred in the staking layer.
	// NOTE: This will NOT trigger for any slashing that happens as part of
	//       any transactions being submitted to the chain.
	slashed := ctx.HasTypedEvent(stakingapp.AppName, &staking.TakeEscrowEvent{})
	// Check if epoch has changed.
	// TODO: We'll later have this for each type of committee.
	epochChanged, epoch := app.state.EpochChanged(ctx)

	if epochChanged || slashed {
		// The 0th epoch will not have suitable entropy for elections, nor
		// will it have useful node registrations.
		baseEpoch, err := app.state.GetBaseEpoch()
		if err != nil {
			return fmt.Errorf("tendermint/scheduler: cound't get base epoch: %w", err)
		}

		if epoch == baseEpoch {
			ctx.Logger().Info("system in bootstrap period, skipping election",
				"epoch", epoch,
			)
			return nil
		}

		state := schedulerState.NewMutableState(ctx.State())
		params, err := state.ConsensusParameters(ctx)
		if err != nil {
			ctx.Logger().Error("failed to fetch consensus parameters",
				"err", err,
			)
			return err
		}

		beaconState := beaconState.NewMutableState(ctx.State())
		beaconParameters, err := beaconState.ConsensusParameters(ctx)
		if err != nil {
			return fmt.Errorf("tendermint/scheduler: couldn't get beacon parameters: %w", err)
		}
		// If weak alphas are allowed then skip the eligibility check as
		// well because the byzantine node and associated tests are extremely
		// fragile, and breaks in hard-to-debug ways if timekeeping isn't
		// exactly how it expects.
		filterCommitteeNodes := beaconParameters.Backend == beacon.BackendVRF && !params.DebugAllowWeakAlpha

		regState := registryState.NewMutableState(ctx.State())
		runtimes, err := regState.Runtimes(ctx)
		if err != nil {
			return fmt.Errorf("tendermint/scheduler: couldn't get runtimes: %w", err)
		}
		allNodes, err := regState.Nodes(ctx)
		if err != nil {
			return fmt.Errorf("tendermint/scheduler: couldn't get nodes: %w", err)
		}

		// Filter nodes.
		var nodes, committeeNodes []*node.Node
		for _, node := range allNodes {
			var status *registry.NodeStatus
			status, err = regState.NodeStatus(ctx, node.ID)
			if err != nil {
				return fmt.Errorf("tendermint/scheduler: couldn't get node status: %w", err)
			}

			// Nodes which are currently frozen cannot be scheduled.
			if status.IsFrozen() {
				continue
			}
			// Expired nodes cannot be scheduled (nodes can be expired and not yet removed).
			if node.IsExpired(uint64(epoch)) {
				continue
			}

			nodes = append(nodes, node)
			if !filterCommitteeNodes || (status.ElectionEligibleAfter != beacon.EpochInvalid && epoch > status.ElectionEligibleAfter) {
				committeeNodes = append(committeeNodes, node)
			}
		}

		var stakeAcc *stakingState.StakeAccumulatorCache
		if !params.DebugBypassStake {
			stakeAcc, err = stakingState.NewStakeAccumulatorCache(ctx)
			if err != nil {
				return fmt.Errorf("tendermint/scheduler: failed to create stake accumulator cache: %w", err)
			}
			defer stakeAcc.Discard()
		}

		var entitiesEligibleForReward map[staking.Address]bool
		if epochChanged {
			// For elections on epoch changes, distribute rewards to entities with any eligible nodes.
			entitiesEligibleForReward = make(map[staking.Address]bool)
		}

		// Handle the validator election first, because no consensus is
		// catastrophic, while failing to elect other committees is not.
		var validatorEntities map[staking.Address]bool
		if validatorEntities, err = app.electValidators(
			ctx,
			app.state,
			beaconState,
			beaconParameters,
			stakeAcc,
			entitiesEligibleForReward,
			nodes,
			params,
		); err != nil {
			// It is unclear what the behavior should be if the validator
			// election fails.  The system can not ensure integrity, so
			// presumably manual intervention is required...
			return fmt.Errorf("tendermint/scheduler: couldn't elect validators: %w", err)
		}

		kinds := []scheduler.CommitteeKind{
			scheduler.KindComputeExecutor,
		}
		for _, kind := range kinds {
			if err = app.electAllCommittees(
				ctx,
				app.state,
				params,
				beaconState,
				beaconParameters,
				stakeAcc,
				entitiesEligibleForReward,
				validatorEntities,
				runtimes,
				committeeNodes,
				kind,
			); err != nil {
				return fmt.Errorf("tendermint/scheduler: couldn't elect %s committees: %w", kind, err)
			}
		}
		ctx.EmitEvent(api.NewEventBuilder(app.Name()).Attribute(KeyElected, cbor.Marshal(kinds)))

		var kindNames []string
		for _, kind := range kinds {
			kindNames = append(kindNames, kind.String())
		}
		var runtimeIDs []string
		for _, rt := range runtimes {
			runtimeIDs = append(runtimeIDs, rt.ID.String())
		}
		ctx.Logger().Debug("finished electing committees",
			"epoch", epoch,
			"kinds", kindNames,
			"runtimes", runtimeIDs,
		)

		if entitiesEligibleForReward != nil {
			accountAddrs := stakingAddressMapToSortedSlice(entitiesEligibleForReward)
			stakingSt := stakingState.NewMutableState(ctx.State())
			if err = stakingSt.AddRewards(ctx, epoch, &params.RewardFactorEpochElectionAny, accountAddrs); err != nil {
				return fmt.Errorf("tendermint/scheduler: failed to add rewards: %w", err)
			}
		}
	}
	return nil
}

func (app *schedulerApplication) ExecuteMessage(ctx *api.Context, kind, msg interface{}) (interface{}, error) {
	return nil, fmt.Errorf("scheduler: unexpected message")
}

func (app *schedulerApplication) ExecuteTx(ctx *api.Context, tx *transaction.Transaction) error {
	return fmt.Errorf("tendermint/scheduler: unexpected transaction")
}

func diffValidators(logger *logging.Logger, current, pending map[signature.PublicKey]int64) []types.ValidatorUpdate {
	var updates []types.ValidatorUpdate
	for v := range current {
		if _, ok := pending[v]; !ok {
			// Existing validator is not part of the new set, reduce its
			// voting power to 0, to indicate removal.
			logger.Debug("removing existing validator from validator set",
				"id", v,
			)
			updates = append(updates, api.PublicKeyToValidatorUpdate(v, 0))
		}
	}

	for v, newPower := range pending {
		if curPower, ok := current[v]; ok && curPower == newPower {
			logger.Debug("keeping existing validator in the validator set",
				"id", v,
			)
			continue
		}
		// We're adding this validator or changing its power.
		logger.Debug("upserting validator to validator set",
			"id", v,
			"power", newPower,
		)
		updates = append(updates, api.PublicKeyToValidatorUpdate(v, newPower))
	}
	return updates
}

func (app *schedulerApplication) EndBlock(ctx *api.Context, req types.RequestEndBlock) (types.ResponseEndBlock, error) {
	var resp types.ResponseEndBlock

	state := schedulerState.NewMutableState(ctx.State())
	pendingValidators, err := state.PendingValidators(ctx)
	if err != nil {
		return resp, fmt.Errorf("scheduler/tendermint: failed to query pending validators: %w", err)
	}
	if pendingValidators == nil {
		// No validator updates to apply.
		return resp, nil
	}

	currentValidators, err := state.CurrentValidators(ctx)
	if err != nil {
		return resp, fmt.Errorf("scheduler/tendermint: failed to query current validators: %w", err)
	}

	// Clear out the pending validator update.
	if err = state.PutPendingValidators(ctx, nil); err != nil {
		return resp, fmt.Errorf("scheduler/tendermint: failed to clear validators: %w", err)
	}

	// Tendermint expects a vector of ValidatorUpdate that expresses
	// the difference between the current validator set (tracked manually
	// from InitChain), and the new validator set, which is a huge pain
	// in the ass.

	resp.ValidatorUpdates = diffValidators(ctx.Logger(), currentValidators, pendingValidators)

	// Stash the updated validator set.
	if err = state.PutCurrentValidators(ctx, pendingValidators); err != nil {
		return resp, fmt.Errorf("scheduler/tendermint: failed to set validators: %w", err)
	}

	return resp, nil
}

func (app *schedulerApplication) isSuitableExecutorWorker(ctx *api.Context, n *node.Node, rt *registry.Runtime) bool {
	if !n.HasRoles(node.RoleComputeWorker) {
		return false
	}
	for _, nrt := range n.Runtimes {
		if !nrt.ID.Equal(&rt.ID) {
			continue
		}
		if nrt.Version.MaskNonMajor() != rt.Version.Version.MaskNonMajor() {
			return false
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
			if err := nrt.Capabilities.TEE.Verify(ctx.Now(), rt.Version.TEE); err != nil {
				ctx.Logger().Warn("failed to verify node TEE attestaion",
					"err", err,
					"node", n,
					"time_stamp", ctx.Now(),
					"runtime", rt.ID,
				)
				return false
			}
			return true
		}
	}
	return false
}

// GetPerm generates a permutation that we use to choose nodes from a list of eligible nodes to elect.
func GetPerm(beacon []byte, runtimeID common.Namespace, rngCtx []byte, nrNodes int) ([]int, error) {
	drbg, err := drbg.New(crypto.SHA512, beacon, runtimeID[:], rngCtx)
	if err != nil {
		return nil, fmt.Errorf("tendermint/scheduler: couldn't instantiate DRBG: %w", err)
	}
	rng := rand.New(mathrand.New(drbg))
	return rng.Perm(nrNodes), nil
}

// Operates on consensus connection.
func (app *schedulerApplication) electAllCommittees(
	ctx *api.Context,
	appState api.ApplicationQueryState,
	schedulerParameters *scheduler.ConsensusParameters,
	beaconState *beaconState.MutableState,
	beaconParameters *beacon.ConsensusParameters,
	stakeAcc *stakingState.StakeAccumulatorCache,
	entitiesEligibleForReward map[staking.Address]bool,
	validatorEntities map[staking.Address]bool,
	runtimes []*registry.Runtime,
	nodeList []*node.Node,
	kind scheduler.CommitteeKind,
) error {
	for _, runtime := range runtimes {
		if err := app.electCommittee(
			ctx,
			appState,
			schedulerParameters,
			beaconState,
			beaconParameters,
			stakeAcc,
			entitiesEligibleForReward,
			validatorEntities,
			runtime,
			nodeList,
			kind,
		); err != nil {
			return err
		}
	}
	return nil
}

func (app *schedulerApplication) electValidators(
	ctx *api.Context,
	appState api.ApplicationQueryState,
	beaconState *beaconState.MutableState,
	beaconParameters *beacon.ConsensusParameters,
	stakeAcc *stakingState.StakeAccumulatorCache,
	entitiesEligibleForReward map[staking.Address]bool,
	nodes []*node.Node,
	params *scheduler.ConsensusParameters,
) (map[staking.Address]bool, error) {
	// Filter the node list based on eligibility and minimum required
	// entity stake.
	var nodeList []*node.Node
	entities := make(map[staking.Address]bool)
	for _, n := range nodes {
		if !n.HasRoles(node.RoleValidator) {
			continue
		}
		entAddr := staking.NewAddress(n.EntityID)
		if stakeAcc != nil {
			if err := stakeAcc.CheckStakeClaims(entAddr); err != nil {
				continue
			}
		}
		nodeList = append(nodeList, n)
		entities[entAddr] = true
	}

	// Sort all of the entities that are actually running eligible validator
	// nodes by descending stake.
	weakEntropy, err := beaconState.Beacon(ctx)
	if err != nil {
		return nil, fmt.Errorf("tendermint/scheduler: couldn't get beacon: %w", err)
	}
	sortedEntities, err := stakingAddressMapToSliceByStake(entities, stakeAcc, weakEntropy)
	if err != nil {
		return nil, err
	}

	// Shuffle the node list.
	shuffledNodes, err := shuffleValidators(ctx, appState, params, beaconState, beaconParameters, nodeList)
	if err != nil {
		return nil, err
	}

	// Gather all the entities nodes.  If the entity has more than one node,
	// ordering will be deterministically random due to the shuffle.
	entityNodesMap := make(map[staking.Address][]*node.Node)
	for i := range shuffledNodes {
		n := shuffledNodes[i] // This is due to the use of append.

		entityAddress := staking.NewAddress(n.EntityID)
		entityNodes := entityNodesMap[entityAddress]
		entityNodes = append(entityNodes, n)
		entityNodesMap[entityAddress] = entityNodes
	}

	// Go down the list of entities running nodes by stake, picking one node
	// to act as a validator till the maximum is reached.
	validatorEntities := make(map[staking.Address]bool)
	newValidators := make(map[signature.PublicKey]int64)
electLoop:
	for _, entAddr := range sortedEntities {
		nodes := entityNodesMap[entAddr]

		// This is usually a maximum of 1, but if more are allowed,
		// like in certain test scenarios, then pick as many nodes
		// as the entity's stake allows
		for i := 0; i < params.MaxValidatorsPerEntity; i++ {
			if i >= len(nodes) {
				break
			}

			n := nodes[i]

			// If the entity gets a validator elected, it is eligible
			// for rewards, but only once regardless of the number
			// of validators owned by the entity in the set.
			if entitiesEligibleForReward != nil {
				entitiesEligibleForReward[entAddr] = true
			}

			var power int64
			if stakeAcc == nil {
				// In simplified no-stake deployments, make validators have flat voting power.
				power = 1
			} else {
				var stake *quantity.Quantity
				stake, err = stakeAcc.GetEscrowBalance(entAddr)
				if err != nil {
					return nil, fmt.Errorf("failed to fetch escrow balance for account %s: %w", entAddr, err)
				}
				power, err = scheduler.VotingPowerFromStake(stake)
				if err != nil {
					return nil, fmt.Errorf("computing voting power for account %s with balance %v: %w",
						entAddr, stake, err,
					)
				}
			}

			validatorEntities[entAddr] = true
			newValidators[n.Consensus.ID] = power
			if len(newValidators) >= params.MaxValidators {
				break electLoop
			}
		}
	}

	if len(newValidators) == 0 {
		return nil, fmt.Errorf("tendermint/scheduler: failed to elect any validators")
	}
	if len(newValidators) < params.MinValidators {
		return nil, fmt.Errorf("tendermint/scheduler: insufficient validators")
	}

	// Set the new pending validator set in the ABCI state.  It needs to be
	// applied in EndBlock.
	state := schedulerState.NewMutableState(ctx.State())
	if err = state.PutPendingValidators(ctx, newValidators); err != nil {
		return nil, fmt.Errorf("failed to set pending validators: %w", err)
	}

	return validatorEntities, nil
}

func stakingAddressMapToSliceByStake(
	entMap map[staking.Address]bool,
	stakeAcc *stakingState.StakeAccumulatorCache,
	beacon []byte,
) ([]staking.Address, error) {
	// Convert the map of entity's stake account addresses to a lexicographically
	// sorted slice (i.e. make it deterministic).
	entities := stakingAddressMapToSortedSlice(entMap)

	// Shuffle the sorted slice to make tie-breaks "random".
	drbg, err := drbg.New(crypto.SHA512, beacon, nil, RNGContextEntities)
	if err != nil {
		return nil, fmt.Errorf("tendermint/scheduler: couldn't instantiate DRBG: %w", err)
	}
	rngSrc := mathrand.New(drbg)
	rng := rand.New(rngSrc)

	rng.Shuffle(len(entities), func(i, j int) {
		entities[i], entities[j] = entities[j], entities[i]
	})

	if stakeAcc == nil {
		return entities, nil
	}

	// Stable-sort the shuffled slice by descending escrow balance.
	var balanceErr error
	sort.SliceStable(entities, func(i, j int) bool {
		iBal, err := stakeAcc.GetEscrowBalance(entities[i])
		if err != nil {
			balanceErr = err
			return false
		}
		jBal, err := stakeAcc.GetEscrowBalance(entities[j])
		if err != nil {
			balanceErr = err
			return false
		}
		return iBal.Cmp(jBal) == 1 // Note: Not -1 to get a reversed sort.
	})
	if balanceErr != nil {
		return nil, fmt.Errorf("failed to fetch escrow balance: %w", balanceErr)
	}

	return entities, nil
}

func stakingAddressMapToSortedSlice(m map[staking.Address]bool) []staking.Address {
	sorted := make([]staking.Address, 0, len(m))
	for mk := range m {
		sorted = append(sorted, mk)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})
	return sorted
}

// New constructs a new scheduler application instance.
func New() api.Application {
	return &schedulerApplication{}
}
