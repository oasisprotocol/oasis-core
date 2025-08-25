package api

import (
	"context"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	if !flags.DebugDontBlameOasis() {
		if p.DebugAllowUnroutableAddresses || p.DebugDeployImmediately {
			return fmt.Errorf("one or more unsafe debug flags set")
		}
		if p.MaxNodeExpiration == 0 {
			return fmt.Errorf("maximum node expiration not specified")
		}
	}
	return nil
}

// SanityCheck performs a sanity check on the consensus parameter changes.
func (c *ConsensusParameterChanges) SanityCheck() error {
	if c.DisableRuntimeRegistration == nil &&
		c.DisableKeyManagerRuntimeRegistration == nil &&
		c.GasCosts == nil &&
		c.MaxNodeExpiration == nil &&
		c.EnableRuntimeGovernanceModels == nil &&
		c.TEEFeatures == nil {
		return fmt.Errorf("consensus parameter changes should not be empty")
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(
	now time.Time,
	height uint64,
	baseEpoch beacon.EpochTime,
	publicKeyBlacklist map[signature.PublicKey]bool,
	escrows map[staking.Address]*staking.EscrowAccount,
) error {
	logger := logging.NewNopLogger()

	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("registry: sanity check failed: %w", err)
	}

	// Check entities.
	seenEntities, err := SanityCheckEntities(logger, g.Entities)
	if err != nil {
		return err
	}

	// Check runtimes.
	runtimesLookup, err := SanityCheckRuntimes(logger, &g.Parameters, g.Runtimes, g.SuspendedRuntimes, true, baseEpoch)
	if err != nil {
		return err
	}

	// Check nodes.
	nodeLookup, err := SanityCheckNodes(logger, &g.Parameters, g.Nodes, seenEntities, runtimesLookup, true, baseEpoch, now, height)
	if err != nil {
		return err
	}

	// Check for blacklisted public keys.
	entities := []*entity.Entity{}
	for k, ent := range seenEntities {
		if publicKeyBlacklist[k] {
			return fmt.Errorf("registry: sanity check failed: entity public key blacklisted: '%s'", k)
		}
		entities = append(entities, ent)
	}
	allRuntimes, err := runtimesLookup.AllRuntimes(context.Background())
	if err != nil {
		return fmt.Errorf("registry: sanity check failed: could not obtain all runtimes from runtimesLookup: %w", err)
	}
	for _, rt := range allRuntimes {
		if publicKeyBlacklist[rt.EntityID] {
			return fmt.Errorf("registry: sanity check failed: runtime '%s' owned by blacklisted entity: '%s'", rt.ID, rt.EntityID)
		}
	}
	for k := range publicKeyBlacklist {
		if node, _ := nodeLookup.NodeBySubKey(context.Background(), k); node != nil {
			return fmt.Errorf("registry: sanity check failed: node '%s' uses blacklisted key: '%s'", node.ID, k)
		}
	}

	// Add stake claims.
	nodes, err := nodeLookup.Nodes(context.Background())
	if err != nil {
		return fmt.Errorf("registry: sanity check failed: could not obtain node list from nodeLookup: %w", err)
	}

	// Skip suspended runtimes for computing stake claims.
	runtimes, err := runtimesLookup.Runtimes(context.Background())
	if err != nil {
		return fmt.Errorf("registry: sanity check failed: could not obtain runtimes from runtimesLookup: %w", err)
	}

	return AddStakeClaims(entities, nodes, runtimes, allRuntimes, escrows)
}

// SanityCheckEntities examines the entities table.
// Returns lookup of entity ID to the entity record for use in other checks.
func SanityCheckEntities(logger *logging.Logger, entities []*entity.SignedEntity) (map[signature.PublicKey]*entity.Entity, error) {
	seenEntities := make(map[signature.PublicKey]*entity.Entity)
	for _, signedEnt := range entities {
		entity, err := VerifyRegisterEntityArgs(logger, signedEnt, true, true)
		if err != nil {
			return nil, fmt.Errorf("entity sanity check failed: %w", err)
		}
		seenEntities[entity.ID] = entity
	}

	return seenEntities, nil
}

// SanityCheckRuntimes examines the runtimes table.
func SanityCheckRuntimes(
	logger *logging.Logger,
	params *ConsensusParameters,
	runtimes []*Runtime,
	suspendedRuntimes []*Runtime,
	isGenesis bool,
	now beacon.EpochTime,
) (RuntimeLookup, error) {
	// First go through all runtimes and perform general sanity checks.
	seenRuntimes := []*Runtime{}
	for _, rt := range runtimes {
		if err := VerifyRuntime(params, logger, rt, isGenesis, true, now); err != nil {
			return nil, fmt.Errorf("runtime sanity check failed: %w", err)
		}
		seenRuntimes = append(seenRuntimes, rt)
	}

	seenSuspendedRuntimes := []*Runtime{}
	for _, rt := range suspendedRuntimes {
		if err := VerifyRuntime(params, logger, rt, isGenesis, true, now); err != nil {
			return nil, fmt.Errorf("runtime sanity check failed: %w", err)
		}
		seenSuspendedRuntimes = append(seenSuspendedRuntimes, rt)
	}

	// Then build a runtime lookup table and re-check compute runtimes as those need to reference
	// correct key manager runtimes when a key manager is configured.
	lookup, err := newSanityCheckRuntimeLookup(seenRuntimes, seenSuspendedRuntimes)
	if err != nil {
		return nil, fmt.Errorf("runtime sanity check failed: %w", err)
	}
	for _, runtimes := range [][]*Runtime{seenRuntimes, seenSuspendedRuntimes} {
		for _, rt := range runtimes {
			if rt.Kind != KindCompute {
				continue
			}
			if err := VerifyRegisterComputeRuntimeArgs(context.Background(), logger, rt, lookup); err != nil {
				return nil, fmt.Errorf("compute runtime sanity check failed: %w", err)
			}
		}
	}
	return lookup, nil
}

// SanityCheckNodes examines the nodes table.
// Pass lookups of entities and runtimes from SanityCheckEntities
// and SanityCheckRuntimes for cross referencing purposes.
func SanityCheckNodes(
	logger *logging.Logger,
	params *ConsensusParameters,
	nodes []*node.MultiSignedNode,
	seenEntities map[signature.PublicKey]*entity.Entity,
	runtimesLookup RuntimeLookup,
	isGenesis bool,
	epoch beacon.EpochTime,
	now time.Time,
	height uint64,
) (NodeLookup, error) { // nolint: gocyclo

	nodeLookup := &sanityCheckNodeLookup{
		nodes: make(map[signature.PublicKey]*node.Node),
	}

	for _, signedNode := range nodes {

		// Open the node to get the referenced entity.
		var n node.Node
		if err := signedNode.Open(RegisterGenesisNodeSignatureContext, &n); err != nil {
			return nil, fmt.Errorf("registry: sanity check failed: unable to open signed node")
		}
		if !n.ID.IsValid() {
			return nil, fmt.Errorf("registry: node sanity check failed: ID %s is invalid", n.ID.String())
		}
		entity, ok := seenEntities[n.EntityID]
		if !ok {
			return nil, fmt.Errorf("registry: node sanity check failed node: %s references a missing entity", n.ID.String())
		}

		node, _, err := VerifyRegisterNodeArgs(
			context.Background(),
			params,
			logger,
			signedNode,
			entity,
			now,
			height,
			isGenesis,
			true,
			epoch,
			runtimesLookup,
			nodeLookup,
		)
		if err != nil {
			return nil, fmt.Errorf("registry: node sanity check failed: ID: %s, error: %w", n.ID.String(), err)
		}

		// Add validated node to nodeLookup.
		nodeLookup.nodes[node.Consensus.ID] = node
		nodeLookup.nodes[node.P2P.ID] = node
		nodeLookup.nodes[node.TLS.PubKey] = node
		nodeLookup.nodesList = append(nodeLookup.nodesList, node)
	}

	return nodeLookup, nil
}

// AddStakeClaims adds stake claims for entities and all their registered nodes
// and runtimes.
func AddStakeClaims(
	entities []*entity.Entity,
	nodes []*node.Node,
	runtimes []*Runtime,
	allRuntimes []*Runtime,
	escrows map[staking.Address]*staking.EscrowAccount,
) error {
	for _, entity := range entities {
		// Add entity stake claim.
		addr := staking.NewAddress(entity.ID)
		escrow, ok := escrows[addr]
		if !ok {
			escrow = &staking.EscrowAccount{}
			escrows[addr] = escrow
		}

		escrow.StakeAccumulator.AddClaimUnchecked(StakeClaimRegisterEntity, staking.GlobalStakeThresholds(staking.KindEntity))
	}

	runtimeMap := make(map[common.Namespace]*Runtime)
	for _, rt := range allRuntimes {
		runtimeMap[rt.ID] = rt
	}

	var nodeRts []*Runtime
	for _, node := range nodes {
		rtMap := make(map[common.Namespace]struct{})
		for _, rt := range node.Runtimes {
			if _, ok := rtMap[rt.ID]; ok {
				continue
			}
			rtMap[rt.ID] = struct{}{}

			nodeRts = append(nodeRts, runtimeMap[rt.ID])
		}

		// Add node stake claims.
		addr := staking.NewAddress(node.EntityID)
		escrow, ok := escrows[addr]
		if !ok {
			escrow = &staking.EscrowAccount{}
			escrows[addr] = escrow
		}

		escrow.StakeAccumulator.AddClaimUnchecked(StakeClaimForNode(node.ID), StakeThresholdsForNode(node, nodeRts))

		// Reuse slice.
		nodeRts = nodeRts[:0]
	}
	for _, rt := range runtimes {
		// Add runtime stake claims.
		addr, ok := rt.StakingAddress()
		if !ok {
			continue
		}
		escrow, ok := escrows[*addr]
		if !ok {
			escrow = &staking.EscrowAccount{}
			escrows[*addr] = escrow
		}

		escrow.StakeAccumulator.AddClaimUnchecked(StakeClaimForRuntime(rt.ID), StakeThresholdsForRuntime(rt))
	}

	return nil
}

// Runtimes lookup used in sanity checks.
type sanityCheckRuntimeLookup struct {
	runtimes          map[common.Namespace]*Runtime
	suspendedRuntimes map[common.Namespace]*Runtime
	allRuntimes       []*Runtime
}

func newSanityCheckRuntimeLookup(runtimes, suspendedRuntimes []*Runtime) (RuntimeLookup, error) {
	rtsMap := make(map[common.Namespace]*Runtime)
	sRtsMap := make(map[common.Namespace]*Runtime)
	allRts := []*Runtime{}
	for _, rt := range runtimes {
		if rtsMap[rt.ID] != nil {
			return nil, fmt.Errorf("duplicate runtime: %s", rt.ID)
		}
		rtsMap[rt.ID] = rt
		allRts = append(allRts, rt)
	}
	for _, srt := range suspendedRuntimes {
		if rtsMap[srt.ID] != nil || sRtsMap[srt.ID] != nil {
			return nil, fmt.Errorf("duplicate (suspended) runtime: %s", srt.ID)
		}
		sRtsMap[srt.ID] = srt
		allRts = append(allRts, srt)
	}
	return &sanityCheckRuntimeLookup{
		runtimes:          rtsMap,
		suspendedRuntimes: sRtsMap,
		allRuntimes:       allRts,
	}, nil
}

func (r *sanityCheckRuntimeLookup) Runtime(_ context.Context, id common.Namespace) (*Runtime, error) {
	rt, ok := r.runtimes[id]
	if !ok {
		return nil, fmt.Errorf("runtime not found")
	}
	return rt, nil
}

func (r *sanityCheckRuntimeLookup) SuspendedRuntime(_ context.Context, id common.Namespace) (*Runtime, error) {
	srt, ok := r.suspendedRuntimes[id]
	if !ok {
		return nil, ErrNoSuchRuntime
	}
	return srt, nil
}

func (r *sanityCheckRuntimeLookup) AnyRuntime(_ context.Context, id common.Namespace) (*Runtime, error) {
	rt, ok := r.runtimes[id]
	if !ok {
		srt, ok := r.suspendedRuntimes[id]
		if !ok {
			return nil, ErrNoSuchRuntime
		}
		return srt, nil
	}
	return rt, nil
}

func (r *sanityCheckRuntimeLookup) AllRuntimes(context.Context) ([]*Runtime, error) {
	return r.allRuntimes, nil
}

func (r *sanityCheckRuntimeLookup) Runtimes(context.Context) ([]*Runtime, error) {
	runtimes := make([]*Runtime, 0, len(r.runtimes))
	for _, r := range r.runtimes {
		runtimes = append(runtimes, r)
	}
	return runtimes, nil
}

// Node lookup used in sanity checks.
type sanityCheckNodeLookup struct {
	nodes map[signature.PublicKey]*node.Node

	nodesList []*node.Node
}

func (n *sanityCheckNodeLookup) NodeBySubKey(_ context.Context, key signature.PublicKey) (*node.Node, error) {
	node, ok := n.nodes[key]
	if !ok {
		return nil, ErrNoSuchNode
	}
	return node, nil
}

func (n *sanityCheckNodeLookup) Nodes(context.Context) ([]*node.Node, error) {
	return n.nodesList, nil
}

func (n *sanityCheckNodeLookup) GetEntityNodes(context.Context, signature.PublicKey) ([]*node.Node, error) {
	return nil, fmt.Errorf("entity node lookup not supported")
}
