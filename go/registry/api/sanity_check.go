package api

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(
	baseEpoch epochtime.EpochTime,
	stakeLedger map[staking.Address]*staking.Account,
	stakeThresholds map[staking.ThresholdKind]quantity.Quantity,
	publicKeyBlacklist map[signature.PublicKey]bool,
) error {
	logger := logging.GetLogger("genesis/sanity-check")

	if !flags.DebugDontBlameOasis() {
		if g.Parameters.DebugAllowUnroutableAddresses || g.Parameters.DebugBypassStake || g.Parameters.DebugAllowEntitySignedNodeRegistration {
			return fmt.Errorf("registry: sanity check failed: one or more unsafe debug flags set")
		}
		if g.Parameters.MaxNodeExpiration == 0 {
			return fmt.Errorf("registry: sanity check failed: maximum node expiration not specified")
		}
	}

	// Check entities.
	seenEntities, err := SanityCheckEntities(logger, g.Entities)
	if err != nil {
		return err
	}

	// Check runtimes.
	runtimesLookup, err := SanityCheckRuntimes(logger, &g.Parameters, g.Runtimes, g.SuspendedRuntimes, true)
	if err != nil {
		return err
	}

	// Check nodes.
	nodeLookup, err := SanityCheckNodes(logger, &g.Parameters, g.Nodes, seenEntities, runtimesLookup, true, baseEpoch)
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
	runtimes, err := runtimesLookup.AllRuntimes(context.Background())
	if err != nil {
		return fmt.Errorf("registry: sanity check failed: could not obtain all runtimes from runtimesLookup: %w", err)
	}
	for _, rt := range runtimes {
		if publicKeyBlacklist[rt.EntityID] {
			return fmt.Errorf("registry: sanity check failed: runtime '%s' owned by blacklisted entity: '%s'", rt.ID, rt.EntityID)
		}
	}
	for k := range publicKeyBlacklist {
		if node, _ := nodeLookup.NodeBySubKey(context.Background(), k); node != nil {
			return fmt.Errorf("registry: sanity check failed: node '%s' uses blacklisted key: '%s'", node.ID, k)
		}
	}

	if !g.Parameters.DebugBypassStake {
		nodes, err := nodeLookup.Nodes(context.Background())
		if err != nil {
			return fmt.Errorf("registry: sanity check failed: could not obtain node list from nodeLookup: %w", err)
		}
		// Check stake.
		return SanityCheckStake(entities, stakeLedger, nodes, runtimes, stakeThresholds, true)
	}

	return nil
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
	runtimes []*SignedRuntime,
	suspendedRuntimes []*SignedRuntime,
	isGenesis bool,
) (RuntimeLookup, error) {
	// First go through all runtimes and perform general sanity checks.
	seenRuntimes := []*Runtime{}
	for _, signedRt := range runtimes {
		rt, err := VerifyRegisterRuntimeArgs(params, logger, signedRt, isGenesis, true)
		if err != nil {
			return nil, fmt.Errorf("runtime sanity check failed: %w", err)
		}
		seenRuntimes = append(seenRuntimes, rt)
	}

	seenSuspendedRuntimes := []*Runtime{}
	for _, signedRt := range suspendedRuntimes {
		rt, err := VerifyRegisterRuntimeArgs(params, logger, signedRt, isGenesis, true)
		if err != nil {
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
	epoch epochtime.EpochTime,
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
			time.Now(),
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

// SanityCheckStake ensures entities' stake accumulator claims are consistent
// with general state and entities have enough stake for themselves and all
// their registered nodes and runtimes.
func SanityCheckStake(
	entities []*entity.Entity,
	accounts map[staking.Address]*staking.Account,
	nodes []*node.Node,
	runtimes []*Runtime,
	stakeThresholds map[staking.ThresholdKind]quantity.Quantity,
	isGenesis bool,
) error {
	// Entities' escrow accounts for checking claims and stake.
	generatedEscrows := make(map[staking.Address]*staking.EscrowAccount)

	// Generate escrow account for all entities.
	for _, entity := range entities {
		var escrow *staking.EscrowAccount
		addr := staking.NewAddress(entity.ID)
		acct, ok := accounts[addr]
		if ok {
			// Generate an escrow account with the same active balance and shares number.
			escrow = &staking.EscrowAccount{
				Active: staking.SharePool{
					Balance:     acct.Escrow.Active.Balance,
					TotalShares: acct.Escrow.Active.TotalShares,
				},
			}
		} else {
			// No account is associated with this entity, generate an empty escrow account.
			escrow = &staking.EscrowAccount{}
		}

		// Add entity stake claim.
		escrow.StakeAccumulator.AddClaimUnchecked(StakeClaimRegisterEntity, staking.GlobalStakeThresholds(staking.KindEntity))

		generatedEscrows[addr] = escrow
	}

	runtimeMap := make(map[common.Namespace]*Runtime)
	for _, rt := range runtimes {
		runtimeMap[rt.ID] = rt
	}
	for _, node := range nodes {
		var nodeRts []*Runtime
		for _, rt := range node.Runtimes {
			nodeRts = append(nodeRts, runtimeMap[rt.ID])
		}
		// Add node stake claims.
		addr := staking.NewAddress(node.EntityID)
		generatedEscrows[addr].StakeAccumulator.AddClaimUnchecked(StakeClaimForNode(node.ID), StakeThresholdsForNode(node, nodeRts))
	}
	for _, rt := range runtimes {
		// Add runtime stake claims.
		addr := staking.NewAddress(rt.EntityID)
		generatedEscrows[addr].StakeAccumulator.AddClaimUnchecked(StakeClaimForRuntime(rt.ID), StakeThresholdsForRuntime(rt))
	}

	// Compare entities' generated escrow accounts with actual ones.
	for _, entity := range entities {
		var generatedEscrow, actualEscrow *staking.EscrowAccount
		addr := staking.NewAddress(entity.ID)
		generatedEscrow = generatedEscrows[addr]
		acct, ok := accounts[addr]
		if ok {
			actualEscrow = &acct.Escrow
		} else {
			// No account is associated with this entity, generate an empty escrow account.
			actualEscrow = &staking.EscrowAccount{}
		}

		if isGenesis {
			// For a Genesis document, check if the entity has enough stake for all its stake claims.
			// NOTE: We can't perform this check at an arbitrary point since the entity could
			// reclaim its stake from the escrow but its nodes and/or runtimes will only be
			// ineligible/suspended at the next epoch transition.
			if err := generatedEscrow.CheckStakeClaims(stakeThresholds); err != nil {
				expected := "unknown"
				expectedQty, err2 := generatedEscrow.StakeAccumulator.TotalClaims(stakeThresholds, nil)
				if err2 == nil {
					expected = expectedQty.String()
				}
				return fmt.Errorf("insufficient stake for account %s (expected: %s got: %s): %w",
					addr,
					expected,
					generatedEscrow.Active.Balance,
					err,
				)
			}
		} else {
			// Otherwise, compare the expected accumulator state with the actual one.
			// NOTE: We can't perform this check for the Genesis document since it is not allowed to
			// have non-empty stake accumulators.
			expectedClaims := generatedEscrows[addr].StakeAccumulator.Claims
			actualClaims := actualEscrow.StakeAccumulator.Claims
			if len(expectedClaims) != len(actualClaims) {
				return fmt.Errorf("incorrect number of stake claims for account %s (expected: %d got: %d)",
					addr,
					len(expectedClaims),
					len(actualClaims),
				)
			}
			for claim, expectedThresholds := range expectedClaims {
				thresholds, ok := actualClaims[claim]
				if !ok {
					return fmt.Errorf("missing claim %s for account %s", claim, addr)
				}
				if len(thresholds) != len(expectedThresholds) {
					return fmt.Errorf("incorrect number of thresholds for claim %s for account %s (expected: %d got: %d)",
						claim,
						addr,
						len(expectedThresholds),
						len(thresholds),
					)
				}
				for i, expectedThreshold := range expectedThresholds {
					threshold := thresholds[i]
					if !threshold.Equal(&expectedThreshold) { // nolint: gosec
						return fmt.Errorf("incorrect threshold in position %d for claim %s for account %s (expected: %s got: %s)",
							i,
							claim,
							addr,
							expectedThreshold,
							threshold,
						)
					}
				}
			}
		}
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

func (r *sanityCheckRuntimeLookup) Runtime(ctx context.Context, id common.Namespace) (*Runtime, error) {
	rt, ok := r.runtimes[id]
	if !ok {
		return nil, fmt.Errorf("runtime not found")
	}
	return rt, nil
}

func (r *sanityCheckRuntimeLookup) SuspendedRuntime(ctx context.Context, id common.Namespace) (*Runtime, error) {
	srt, ok := r.suspendedRuntimes[id]
	if !ok {
		return nil, ErrNoSuchRuntime
	}
	return srt, nil
}

func (r *sanityCheckRuntimeLookup) AnyRuntime(ctx context.Context, id common.Namespace) (*Runtime, error) {
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

func (r *sanityCheckRuntimeLookup) AllRuntimes(ctx context.Context) ([]*Runtime, error) {
	return r.allRuntimes, nil
}

// Node lookup used in sanity checks.
type sanityCheckNodeLookup struct {
	nodes map[signature.PublicKey]*node.Node

	nodesList []*node.Node
}

func (n *sanityCheckNodeLookup) NodeBySubKey(ctx context.Context, key signature.PublicKey) (*node.Node, error) {
	node, ok := n.nodes[key]
	if !ok {
		return nil, ErrNoSuchNode
	}
	return node, nil
}

func (n *sanityCheckNodeLookup) Nodes(ctx context.Context) ([]*node.Node, error) {
	return n.nodesList, nil
}
