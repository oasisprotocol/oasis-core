package scheduler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tuplehash"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	tmBeacon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking/state"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

type nodeWithStatus struct {
	node   *node.Node
	status *registry.NodeStatus
}

func getPrevVRFState(
	ctx *api.Context,
	beaconState *beaconState.MutableState,
) (*beacon.PrevVRFState, error) {
	st, err := beaconState.VRFState(ctx)
	if err != nil {
		return nil, fmt.Errorf("cometbft/scheduler: failed to query VRF state: %w", err)
	}
	return st.PrevState, nil
}

func shuffleValidators(
	ctx *api.Context,
	epoch beacon.EpochTime,
	schedulerParameters *scheduler.ConsensusParameters,
	beaconState *beaconState.MutableState,
	beaconParameters *beacon.ConsensusParameters,
	nodes []*node.Node,
) ([]*node.Node, error) {
	switch beaconParameters.Backend { // Used so that we can break to fallback.
	case beacon.BackendVRF:
		var prevState *beacon.PrevVRFState

		// Do the VRF-based validator shuffle.
		prevState, err := getPrevVRFState(ctx, beaconState)
		if err != nil {
			return nil, err
		}

		var numValidatorsWithPi int
		for _, n := range nodes {
			if prevState.Pi[n.ID] != nil {
				numValidatorsWithPi++
			}
		}
		if numValidatorsWithPi < schedulerParameters.MinValidators {
			// If not enough validators have submitted proofs to
			// ensure that the minimum committee size has been met,
			// fall back to using the weak/insecure entropy source.
			//
			// This isn't great, but it's "only" for tie-breaking
			// when entities have equal stake, so it's probably ok
			// and realistically this situation shouldn't happen.
			ctx.Logger().Warn("insufficient proofs to shuffle validators by hashed betas",
				"epoch", epoch,
				"num_eligible_validators", numValidatorsWithPi,
				"min_validators", schedulerParameters.MinValidators,
			)
			break
		}

		ctx.Logger().Info(
			"validator election: shuffling by hashed betas",
			"epoch", epoch,
			"num_proofs", len(prevState.Pi),
		)

		baseHasher := newBetaHasher(
			[]byte("oasis-core:vrf/validator"),
			tmBeacon.MustGetChainContext(ctx),
			epoch,
		)

		// Do the cryptographic sortition.
		ret := sortNodesByHashedBeta(
			prevState,
			baseHasher,
			nodes,
		)

		return ret, nil
	}

	// Do the old-fashioned entropy-based election.
	//
	// Once we fully migrate to VRF-based elections, and rewrite some of the
	// test cases, this should only be used in the fallback case.
	ctx.Logger().Info(
		"validator election: shuffling by per-epoch entropy",
		"epoch", epoch,
	)

	entropy, err := beaconState.Beacon(ctx)
	if err != nil {
		return nil, fmt.Errorf("cometbft/scheduler: couldn't get beacon: %w", err)
	}

	rng, err := initRNG(entropy, nil, RNGContextValidators)
	if err != nil {
		return nil, err
	}

	return shuffleNodes(nodes, rng)
}

func shuffleNodes(nodes []*node.Node, rng *rand.Rand) ([]*node.Node, error) {
	l := len(nodes)
	idxs := rng.Perm(l)
	shuffled := make([]*node.Node, 0, l)

	for i := range l {
		shuffled = append(shuffled, nodes[idxs[i]])
	}

	return shuffled, nil
}

func electCommittee(
	ctx *api.Context,
	epoch beacon.EpochTime,
	schedulerParameters *scheduler.ConsensusParameters,
	beaconState *beaconState.MutableState,
	beaconParameters *beacon.ConsensusParameters,
	registryParameters *registry.ConsensusParameters,
	stakeAcc *stakingState.StakeAccumulatorCache,
	rewardableEntities map[staking.Address]struct{},
	validatorEntities map[staking.Address]struct{},
	rt *registry.Runtime,
	nodes []*nodeWithStatus,
	kind scheduler.CommitteeKind,
) error {
	ctx.Logger().Debug("electing committee",
		"epoch", epoch,
		"kind", kind,
		"runtime", rt.ID,
	)

	// Only generic compute runtimes need to elect all the committees.
	if !rt.IsCompute() && kind != scheduler.KindComputeExecutor {
		return nil
	}

	members, err := electCommitteeMembers(
		ctx,
		epoch,
		schedulerParameters,
		beaconState,
		beaconParameters,
		registryParameters,
		stakeAcc,
		rewardableEntities,
		validatorEntities,
		rt,
		nodes,
		kind,
	)
	if err != nil {
		return err
	}

	if len(members) == 0 {
		if err := schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
			return fmt.Errorf("cometbft/scheduler: failed to drop committee: %w", err)
		}
		return nil
	}

	committee := &scheduler.Committee{
		Kind:      kind,
		RuntimeID: rt.ID,
		Members:   members,
		ValidFor:  epoch,
	}
	if err := schedulerState.NewMutableState(ctx.State()).PutCommittee(ctx, committee); err != nil {
		return fmt.Errorf("cometbft/scheduler: failed to save committee: %w", err)
	}

	ctx.Logger().Debug("finished electing committee",
		"epoch", epoch,
		"kind", kind,
		"runtime", rt.ID,
	)

	return nil
}

func electCommitteeMembers( //nolint: gocyclo
	ctx *api.Context,
	epoch beacon.EpochTime,
	schedulerParameters *scheduler.ConsensusParameters,
	beaconState *beaconState.MutableState,
	beaconParameters *beacon.ConsensusParameters,
	registryParameters *registry.ConsensusParameters,
	stakeAcc *stakingState.StakeAccumulatorCache,
	rewardableEntities map[staking.Address]struct{},
	validatorEntities map[staking.Address]struct{},
	rt *registry.Runtime,
	nodes []*nodeWithStatus,
	kind scheduler.CommitteeKind,
) ([]*scheduler.CommitteeNode, error) {
	// Workers must be listed before backup workers, as other parts of the code depend on this
	// order for better performance.
	committeeRoles := []scheduler.Role{
		scheduler.RoleWorker,
		scheduler.RoleBackupWorker,
	}

	// Figure out how (beacon backend).
	useVRF := beaconParameters.Backend == beacon.BackendVRF

	// If a VRF-based election is to be done, query the VRF state.
	var (
		prevState *beacon.PrevVRFState
		err       error
	)
	if useVRF {
		if prevState, err = getPrevVRFState(ctx, beaconState); err != nil {
			return nil, err
		}
		if !prevState.CanElectCommittees {
			if !schedulerParameters.DebugAllowWeakAlpha {
				ctx.Logger().Error("epoch had weak VRF alpha, committee elections not allowed",
					"kind", kind,
					"runtime_id", rt.ID,
				)
				return nil, nil
			}

			ctx.Logger().Warn("epoch had weak VRF alpha, debug option set, allowing election anyway",
				"kind", kind,
				"runtime_id", rt.ID,
			)
		}
	}

	// Determine the committee size, and pre-filter the node-list based
	// on eligibility, entity stake and other criteria.

	var isSuitableFn func(*api.Context, *nodeWithStatus, *registry.Runtime, beacon.EpochTime, *registry.ConsensusParameters) bool
	groupSizes := make(map[scheduler.Role]int)
	switch kind {
	case scheduler.KindComputeExecutor:
		isSuitableFn = isSuitableExecutorWorker
		groupSizes[scheduler.RoleWorker] = int(rt.Executor.GroupSize)
		groupSizes[scheduler.RoleBackupWorker] = int(rt.Executor.GroupBackupSize)
	default:
		return nil, fmt.Errorf("cometbft/scheduler: invalid committee type: %v", kind)
	}

	// Ensure that it is theoretically possible to elect a valid committee.
	if groupSizes[scheduler.RoleWorker] == 0 {
		ctx.Logger().Error("empty committee not allowed",
			"kind", kind,
			"runtime_id", rt.ID,
		)
		return nil, nil
	}

	// Decode per-role constraints.
	cs := rt.Constraints[kind]

	// Perform pre-election eligibility filtering.
	nodesPerRole := make(map[scheduler.Role][]*node.Node)
	for _, n := range nodes {
		// Check if an entity has enough stake.
		entAddr := staking.NewAddress(n.node.EntityID)
		if !schedulerParameters.DebugBypassStake {
			if err = stakeAcc.CheckStakeClaims(entAddr); err != nil {
				continue
			}
		}

		// Check general node compatibility.
		if !isSuitableFn(ctx, n, rt, epoch, registryParameters) {
			continue
		}

		// If the election uses VRFs, make sure that the node bothered to submit
		// a VRF proof for this election.
		if useVRF && prevState.Pi[n.node.ID] == nil {
			// ... as long as we aren't testing with mandatory committee
			// members.
			isForceElect := false
			if flags.DebugDontBlameOasis() && schedulerParameters.DebugForceElect != nil {
				if rtNodeMap := schedulerParameters.DebugForceElect[rt.ID]; rtNodeMap != nil {
					if ri := rtNodeMap[n.node.ID]; ri != nil {
						isForceElect = kind == ri.Kind
					}
				}
			}
			if !isForceElect {
				ctx.Logger().Warn("marking node as ineligible for elections, no pi",
					"kind", kind,
					"runtime_id", rt.ID,
					"id", n.node.ID,
				)
				continue
			}
		}

		// Check pre-election scheduling constraints.
		var eligible bool
		for _, role := range committeeRoles {
			if groupSizes[role] == 0 {
				continue
			}

			// Validator set membership constraint.
			if cs[role].ValidatorSet != nil {
				if _, ok := validatorEntities[entAddr]; !ok {
					// Not eligible if not in the validator set.
					continue
				}
			}

			nodesPerRole[role] = append(nodesPerRole[role], n.node)
			eligible = true
		}
		if !eligible {
			continue
		}

		rewardableEntities[entAddr] = struct{}{}
	}

	// Perform election.
	var members []*scheduler.CommitteeNode
	for _, role := range committeeRoles {
		if groupSizes[role] == 0 {
			continue
		}

		// Enforce the maximum node per-entity prior to doing the actual
		// election to reduce "more nodes = more better" problems.  This
		// will ensure fairness if the constraint is set to 1 (as is the
		// case with all currently deployed runtimes with the constraint),
		// but is still not ideal if the constraint is larger.
		nodes := nodesPerRole[role]
		if mn := cs[role].MaxNodes; mn != nil && mn.Limit > 0 {
			if flags.DebugDontBlameOasis() && schedulerParameters.DebugForceElect != nil {
				ctx.Logger().Error("debug force elect is incompatible with de-duplication",
					"kind", kind,
					"role", role,
					"runtime_id", rt.ID,
				)
				return nil, nil
			}

			switch useVRF {
			case false:
				// Just use the first seen nodes in the node list up to
				// the limit, per-entity.  This is only used in testing.
				nodes = dedupEntityNodesTrivial(
					nodes,
					mn.Limit,
				)
			case true:
				nodes = dedupEntityNodesByHashedBeta(
					prevState,
					tmBeacon.MustGetChainContext(ctx),
					epoch,
					rt.ID,
					kind,
					role,
					nodes,
					mn.Limit,
				)
			}
		}
		nrNodes := len(nodes)

		// Check election scheduling constraints.
		var minPoolSize int
		if cs[role].MinPoolSize != nil {
			minPoolSize = int(cs[role].MinPoolSize.Limit)
		}

		if nrNodes < minPoolSize {
			ctx.Logger().Error("not enough eligible nodes",
				"kind", kind,
				"role", role,
				"runtime_id", rt.ID,
				"nr_nodes", nrNodes,
				"min_pool_size", minPoolSize,
			)
			return nil, nil
		}

		wantedNodes := groupSizes[role]
		if wantedNodes > nrNodes {
			ctx.Logger().Error("committee size exceeds available nodes",
				"kind", kind,
				"runtime_id", rt.ID,
				"wanted_nodes", wantedNodes,
				"nr_nodes", nrNodes,
			)
			return nil, nil
		}

		var idxs []int

		switch useVRF {
		case false:
			// Use the per-epoch entropy to do the elections.
			var rngCtx []byte
			switch kind {
			case scheduler.KindComputeExecutor:
				rngCtx = RNGContextExecutor
			}
			switch role {
			case scheduler.RoleWorker:
				rngCtx = append(rngCtx, RNGContextRoleWorker...)
			case scheduler.RoleBackupWorker:
				rngCtx = append(rngCtx, RNGContextRoleBackupWorker...)
			default:
				return nil, fmt.Errorf("cometbft/scheduler: unsupported role: %v", role)
			}

			entropy, err := beaconState.Beacon(ctx)
			if err != nil {
				return nil, fmt.Errorf("cometbft/scheduler: couldn't get beacon: %w", err)
			}

			rng, err := initRNG(entropy, rt.ID[:], rngCtx)
			if err != nil {
				return nil, err
			}
			idxs = rng.Perm(nrNodes)
		case true:
			// Use the VRF proofs to do the elections.
			baseHasher := newCommitteeBetaHasher(
				tmBeacon.MustGetChainContext(ctx),
				epoch,
				rt.ID,
				kind,
				role,
			)

			idxs = committeeVRFBetaIndexes(
				prevState,
				baseHasher,
				nodes,
			)
		}

		// If the election is rigged for testing purposes, force-elect the
		// nodes if possible.
		ok, elected, forceState := debugForceElect(
			ctx,
			schedulerParameters,
			rt,
			kind,
			role,
			nodes,
			wantedNodes,
		)
		if !ok {
			return nil, nil
		}

		// Do the actual election by traversing the randomly sorted node
		// indexes list.
		nodesPerEntity := make(map[signature.PublicKey]int)
		for _, idx := range idxs {
			if len(elected) >= wantedNodes {
				break
			}

			n := nodes[idx]
			if forceState != nil && forceState.elected[n.ID] {
				// Already elected to the committee by the debug forcing option.
				continue
			}

			// Check election-time scheduling constraints.  In theory this
			// is pre-enforced by restricting the number of eligible candidates
			// per entity, but re-checking doesn't hurt.
			if mn := cs[role].MaxNodes; mn != nil {
				if nodesPerEntity[n.EntityID] >= int(mn.Limit) {
					ctx.Logger().Error("max nodes per committee exceeded",
						"runtime", rt.ID,
						"entity_id", n.EntityID,
						"role", role,
						"num_entity_nodes", nodesPerEntity[n.EntityID],
					)
					return nil, nil
				}
				nodesPerEntity[n.EntityID]++
			}

			elected = append(elected, &scheduler.CommitteeNode{
				Role:      role,
				PublicKey: n.ID,
			})
		}

		if len(elected) != wantedNodes {
			ctx.Logger().Error("insufficient nodes that satisfy constraints to elect",
				"kind", kind,
				"role", role,
				"runtime_id", rt.ID,
				"available", len(elected),
			)
			return nil, nil
		}

		// If the election is rigged for testing purposes, fixup the force
		// elected node roles.
		if ok, elected = debugForceRoles(
			ctx,
			forceState,
			elected,
			role,
		); !ok {
			return nil, nil
		}

		members = append(members, elected...)
	}

	return members, nil
}

func committeeVRFBetaIndexes(
	prevState *beacon.PrevVRFState,
	baseHasher *tuplehash.Hasher,
	nodes []*node.Node,
) []int {
	indexByNode := make(map[signature.PublicKey]int)
	for i, n := range nodes {
		indexByNode[n.ID] = i
	}

	sorted := sortNodesByHashedBeta(
		prevState,
		baseHasher,
		nodes,
	)

	ret := make([]int, 0, len(sorted))
	for _, n := range sorted {
		ret = append(ret, indexByNode[n.ID])
	}

	return ret
}

func sortNodesByHashedBeta(
	prevState *beacon.PrevVRFState,
	baseHasher *tuplehash.Hasher,
	nodes []*node.Node,
) []*node.Node {
	// Accumulate the hashed betas.
	nodeByHashedBeta := make(map[hashedBeta]*node.Node)
	betas := make([]hashedBeta, 0, len(nodes))
	for i := range nodes {
		n := nodes[i]
		pi := prevState.Pi[n.ID]
		if pi == nil {
			continue
		}

		beta := hashBeta(baseHasher, pi.UnsafeToHash())
		if nodeByHashedBeta[beta] == nil {
			// These should never collide in practice, but on the off-chance
			// that they do, the first one wins.
			betas = append(betas, beta)
			nodeByHashedBeta[beta] = n
		}
	}

	// Sort based on the hashed VRF digests.
	sort.SliceStable(betas, func(i, j int) bool {
		a, b := betas[i], betas[j]
		return bytes.Compare(a[:], b[:]) < 0
	})

	ret := make([]*node.Node, 0, len(betas))
	for _, beta := range betas {
		ret = append(ret, nodeByHashedBeta[beta])
	}

	return ret
}

type hashedBeta [32]byte

func hashBeta(
	h *tuplehash.Hasher,
	beta []byte,
) hashedBeta {
	hh := h.Clone()
	_, _ = hh.Write(beta)
	digest := hh.Sum(nil)

	var ret hashedBeta
	copy(ret[:], digest)

	return ret
}

func newCommitteeBetaHasher(
	chainContext []byte,
	epoch beacon.EpochTime,
	runtimeID common.Namespace,
	kind scheduler.CommitteeKind,
	role scheduler.Role,
) *tuplehash.Hasher {
	h := newBetaHasher([]byte("oasis-core:vrf/committee"), chainContext, epoch)
	_, _ = h.Write(runtimeID[:])
	_, _ = h.Write([]byte{byte(kind)})
	_, _ = h.Write([]byte{byte(role)})

	return h
}

func newCommitteeDedupBetaHasher(
	chainContext []byte,
	epoch beacon.EpochTime,
	runtimeID common.Namespace,
	kind scheduler.CommitteeKind,
	role scheduler.Role,
) *tuplehash.Hasher {
	h := newBetaHasher([]byte("oasis-core:vrf/dedup"), chainContext, epoch)
	_, _ = h.Write(runtimeID[:])
	_, _ = h.Write([]byte{byte(kind)})
	_, _ = h.Write([]byte{byte(role)})

	return h
}

func newBetaHasher(
	domainSep []byte,
	chainContext []byte,
	epoch beacon.EpochTime,
) *tuplehash.Hasher {
	h := tuplehash.New256(32, domainSep)

	_, _ = h.Write(chainContext)

	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], uint64(epoch))
	_, _ = h.Write(epochBytes[:])

	return h
}

func dedupEntityNodesByHashedBeta(
	prevState *beacon.PrevVRFState,
	chainContext []byte,
	epoch beacon.EpochTime,
	runtimeID common.Namespace,
	kind scheduler.CommitteeKind,
	role scheduler.Role,
	nodes []*node.Node,
	perEntityLimit uint16,
) []*node.Node {
	// If there is no limit, just return.
	if perEntityLimit == 0 {
		return nodes
	}

	baseHasher := newCommitteeDedupBetaHasher(
		chainContext,
		epoch,
		runtimeID,
		kind,
		role,
	)

	// Do the cryptographic sortition.
	shuffled := sortNodesByHashedBeta(
		prevState,
		baseHasher,
		nodes,
	)

	return dedupEntityNodesTrivial(
		shuffled,
		perEntityLimit,
	)
}

func dedupEntityNodesTrivial(
	nodes []*node.Node,
	perEntityLimit uint16,
) []*node.Node {
	nodesPerEntity := make(map[signature.PublicKey]int)
	deduped := make([]*node.Node, 0, len(nodes))
	for i := range nodes {
		n := nodes[i]
		if nodesPerEntity[n.EntityID] >= int(perEntityLimit) {
			continue
		}
		nodesPerEntity[n.EntityID]++
		deduped = append(deduped, n)
	}

	return deduped
}
