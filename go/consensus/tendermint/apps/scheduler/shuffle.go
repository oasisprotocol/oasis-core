package scheduler

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tuplehash"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmBeacon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
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
		return nil, fmt.Errorf("tendermint/scheduler: failed to query VRF state: %w", err)
	}
	return st.PrevState, nil
}

func shuffleValidators(
	ctx *api.Context,
	appState api.ApplicationQueryState,
	schedulerParameters *scheduler.ConsensusParameters,
	beaconState *beaconState.MutableState,
	beaconParameters *beacon.ConsensusParameters,
	nodeList []*node.Node,
) ([]*node.Node, error) {
	epoch, _, err := beaconState.GetEpoch(ctx)
	if err != nil {
		return nil, fmt.Errorf("tendermint/scheduler: failed to query current epoch: %w", err)
	}

	switch { // Used so that we can break to fallback.
	case beaconParameters.Backend == beacon.BackendVRF:
		var prevState *beacon.PrevVRFState

		// Do the VRF-based validator shuffle.
		prevState, err = getPrevVRFState(ctx, beaconState)
		if err != nil {
			return nil, err
		}

		var numValidatorsWithPi int
		for _, v := range nodeList {
			if prevState.Pi[v.ID] != nil {
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
			nodeList,
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
		return nil, fmt.Errorf("tendermint/scheduler: couldn't get beacon: %w", err)
	}
	return shuffleValidatorsByEntropy(entropy, nodeList)
}

func shuffleValidatorsByEntropy(
	entropy []byte,
	nodeList []*node.Node,
) ([]*node.Node, error) {
	drbg, err := drbg.New(crypto.SHA512, entropy, nil, RNGContextValidators)
	if err != nil {
		return nil, fmt.Errorf("tendermint/scheduler: couldn't instantiate DRBG: %w", err)
	}
	rng := rand.New(mathrand.New(drbg))

	l := len(nodeList)
	idxs := rng.Perm(l)
	shuffled := make([]*node.Node, 0, l)

	for i := 0; i < l; i++ {
		shuffled = append(shuffled, nodeList[idxs[i]])
	}

	return shuffled, nil
}

func (app *schedulerApplication) electCommittee( //nolint: gocyclo
	ctx *api.Context,
	appState api.ApplicationQueryState,
	schedulerParameters *scheduler.ConsensusParameters,
	beaconState *beaconState.MutableState,
	beaconParameters *beacon.ConsensusParameters,
	stakeAcc *stakingState.StakeAccumulatorCache,
	entitiesEligibleForReward map[staking.Address]bool,
	validatorEntities map[staking.Address]bool,
	rt *registry.Runtime,
	nodeList []*nodeWithStatus,
	kind scheduler.CommitteeKind,
) error {
	// Only generic compute runtimes need to elect all the committees.
	if !rt.IsCompute() && kind != scheduler.KindComputeExecutor {
		return nil
	}

	// Figure out the when (epoch) and how (beacon backend).
	epoch, _, err := beaconState.GetEpoch(ctx)
	if err != nil {
		return fmt.Errorf("tendermint/scheduler: failed to query current epoch: %w", err)
	}
	useVRF := beaconParameters.Backend == beacon.BackendVRF

	// If a VRF-based election is to be done, query the VRF state.
	var prevState *beacon.PrevVRFState
	if useVRF {
		if prevState, err = getPrevVRFState(ctx, beaconState); err != nil {
			return err
		}
		if !prevState.CanElectCommittees {
			if !schedulerParameters.DebugAllowWeakAlpha {
				ctx.Logger().Error("epoch had weak VRF alpha, committee elections not allowed",
					"kind", kind,
					"runtime_id", rt.ID,
				)
				if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
					return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
				}
				return nil
			}

			ctx.Logger().Warn("epoch had weak VRF alpha, debug option set, allowing election anyway",
				"kind", kind,
				"runtime_id", rt.ID,
			)
		}
	}

	// Determine the committee size, and pre-filter the node-list based
	// on eligibility, entity stake and other criteria.

	var isSuitableFn func(*api.Context, *nodeWithStatus, *registry.Runtime, beacon.EpochTime) bool
	groupSizes := make(map[scheduler.Role]int)
	switch kind {
	case scheduler.KindComputeExecutor:
		isSuitableFn = app.isSuitableExecutorWorker
		groupSizes[scheduler.RoleWorker] = int(rt.Executor.GroupSize)
		groupSizes[scheduler.RoleBackupWorker] = int(rt.Executor.GroupBackupSize)
	default:
		return fmt.Errorf("tendermint/scheduler: invalid committee type: %v", kind)
	}

	// Ensure that it is theoretically possible to elect a valid committee.
	if groupSizes[scheduler.RoleWorker] == 0 {
		ctx.Logger().Error("empty committee not allowed",
			"kind", kind,
			"runtime_id", rt.ID,
		)
		if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
			return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
		}
		return nil
	}

	// Decode per-role constraints.
	cs := rt.Constraints[kind]

	// Perform pre-election eligiblity filtering.
	nodeLists := make(map[scheduler.Role][]*node.Node)
	for _, n := range nodeList {
		// Check if an entity has enough stake.
		entAddr := staking.NewAddress(n.node.EntityID)
		if stakeAcc != nil {
			if err = stakeAcc.CheckStakeClaims(entAddr); err != nil {
				continue
			}
		}
		// Check general node compatibility.
		if !isSuitableFn(ctx, n, rt, epoch) {
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
		for _, role := range []scheduler.Role{scheduler.RoleWorker, scheduler.RoleBackupWorker} {
			if groupSizes[role] == 0 {
				continue
			}

			// Validator set membership constraint.
			if cs[role].ValidatorSet != nil {
				if !validatorEntities[entAddr] {
					// Not eligible if not in the validator set.
					continue
				}
			}

			nodeLists[role] = append(nodeLists[role], n.node)
			eligible = true
		}
		if !eligible {
			continue
		}

		if entitiesEligibleForReward != nil {
			entitiesEligibleForReward[entAddr] = true
		}
	}

	// Perform election.
	var members []*scheduler.CommitteeNode
	for _, role := range []scheduler.Role{scheduler.RoleWorker, scheduler.RoleBackupWorker} {
		if groupSizes[role] == 0 {
			continue
		}

		nrNodes := len(nodeLists[role])

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
			if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
				return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
			}
			return nil
		}

		wantedNodes := groupSizes[role]
		if wantedNodes > nrNodes {
			ctx.Logger().Error("committee size exceeds available nodes",
				"kind", kind,
				"runtime_id", rt.ID,
				"wanted_nodes", wantedNodes,
				"nr_nodes", nrNodes,
			)
			if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
				return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
			}
			return nil
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
				return fmt.Errorf("tendermint/scheduler: unsupported role: %v", role)
			}

			var entropy []byte
			if entropy, err = beaconState.Beacon(ctx); err != nil {
				return fmt.Errorf("tendermint/scheduler: couldn't get beacon: %w", err)
			}

			idxs, err = GetPerm(entropy, rt.ID, rngCtx, nrNodes)
			if err != nil {
				return fmt.Errorf("failed to derive permutation: %w", err)
			}
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
				nodeLists[role],
			)
		}

		var elected []*scheduler.CommitteeNode
		nodesPerEntity := make(map[signature.PublicKey]int)
		forceElected := make(map[signature.PublicKey]bool)
		forceParams := make(map[signature.PublicKey]scheduler.ForceElectCommitteeRole)
		if flags.DebugDontBlameOasis() && schedulerParameters.DebugForceElect != nil {
			var toForce []signature.PublicKey
			for nodeID, ri := range schedulerParameters.DebugForceElect[rt.ID] {
				if kind == ri.Kind && role == ri.Role {
					toForce = append(toForce, nodeID)
					forceParams[nodeID] = *ri
				}
			}
			sort.SliceStable(toForce, func(i, j int) bool {
				a, b := toForce[i], toForce[j]
				return bytes.Compare(a[:], b[:]) < 0
			})
		forceLoop:
			for _, nodeID := range toForce {
				ctx.Logger().Debug("attempting to force-elect node",
					"runtime", rt.ID,
					"node", nodeID,
					"role", role,
				)
				if len(elected) >= wantedNodes {
					break
				}

				// Ensure the node is currently registered and eligible.
				for _, v := range nodeLists[role] {
					ctx.Logger().Debug("checking to see if this is the force elected node",
						"iter_id", v.ID,
						"node", nodeID,
					)
					if v.ID.Equal(nodeID) {
						// And force it into the committee.
						elected = append(elected, &scheduler.CommitteeNode{
							Role:      role,
							PublicKey: nodeID,
						})
						forceElected[nodeID] = true
						ctx.Logger().Debug("force elected node to committee",
							"runtime", rt.ID,
							"node", nodeID,
							"role", role,
						)
						continue forceLoop
					}
				}
			}
			if len(elected) != len(toForce) {
				ctx.Logger().Error("available nodes can't fulfill forced committee members",
					"kind", kind,
					"runtime_id", rt.ID,
					"nr_nodes", nrNodes,
					"mandatory_nodes", len(toForce),
				)
				if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
					return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
				}
				return nil
			}
		}
		for _, idx := range idxs {
			if len(elected) >= wantedNodes {
				break
			}

			n := nodeLists[role][idx]
			if forceElected[n.ID] {
				// Already elected to the committee by the debug forcing option.
				continue
			}

			// Check election-time scheduling constraints.
			if mn := cs[role].MaxNodes; mn != nil {
				if nodesPerEntity[n.EntityID] >= int(mn.Limit) {
					continue
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
			if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
				return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
			}
			return nil
		}

		if flags.DebugDontBlameOasis() && len(forceElected) > 0 {
			var (
				mustBeScheduler    *scheduler.CommitteeNode
				mustNotBeScheduler []*scheduler.CommitteeNode
				mayBeAny           []*scheduler.CommitteeNode
			)

			for i, n := range elected {
				committeeNode := elected[i]
				if ri, ok := forceParams[n.PublicKey]; ok {
					if ri.IsScheduler {
						if mustBeScheduler != nil {
							ctx.Logger().Error("already have a forced scheduler",
								"existing", mustBeScheduler.PublicKey,
								"new", n.PublicKey,
							)
							if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
								return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
							}
							return nil
						}
						mustBeScheduler = committeeNode
					} else {
						mustNotBeScheduler = append(mustNotBeScheduler, committeeNode)
					}
				} else {
					mayBeAny = append(mayBeAny, committeeNode)
				}
			}

			if mustBeScheduler == nil {
				if len(mayBeAny) == 0 && len(mustNotBeScheduler) > 0 {
					ctx.Logger().Error("can't fulfil not committee scheduler requirements")
					if err = schedulerState.NewMutableState(ctx.State()).DropCommittee(ctx, kind, rt.ID); err != nil {
						return fmt.Errorf("tendermint/scheduler: failed to drop committee: %w", err)
					}
					return nil
				}
				mustBeScheduler = mayBeAny[0]
				mayBeAny = mayBeAny[1:]
			}

			elected = []*scheduler.CommitteeNode{mustBeScheduler}
			elected = append(elected, mustNotBeScheduler...)
			elected = append(elected, mayBeAny...)
		}

		members = append(members, elected...)
	}

	committee := &scheduler.Committee{
		Kind:      kind,
		RuntimeID: rt.ID,
		Members:   members,
		ValidFor:  epoch,
	}
	if err = schedulerState.NewMutableState(ctx.State()).PutCommittee(ctx, committee); err != nil {
		return fmt.Errorf("tendermint/scheduler: failed to save committee: %w", err)
	}
	return nil
}

func committeeVRFBetaIndexes(
	prevState *beacon.PrevVRFState,
	baseHasher *tuplehash.Hasher,
	nodeList []*node.Node,
) []int {
	indexByNode := make(map[signature.PublicKey]int)
	for i, n := range nodeList {
		indexByNode[n.ID] = i
	}

	sorted := sortNodesByHashedBeta(
		prevState,
		baseHasher,
		nodeList,
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
	nodeList []*node.Node,
) []*node.Node {
	// Accumulate the hashed betas.
	nodeByHashedBeta := make(map[hashedBeta]*node.Node)
	betas := make([]hashedBeta, 0, len(nodeList))
	for i := range nodeList {
		n := nodeList[i]
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

func hashBeta(h *tuplehash.Hasher, beta []byte) hashedBeta {
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

func newBetaHasher(domainSep, chainContext []byte, epoch beacon.EpochTime) *tuplehash.Hasher {
	h := tuplehash.New256(32, domainSep)

	_, _ = h.Write(chainContext)

	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], uint64(epoch))
	_, _ = h.Write(epochBytes[:])

	return h
}
