package api

import (
	"context"
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
)

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(baseEpoch epochtime.EpochTime) error {
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
	return SanityCheckNodes(logger, &g.Parameters, g.Nodes, seenEntities, runtimesLookup, true, baseEpoch)
}

// SanityCheckEntities examines the entities table.
// Returns lookup of entity ID to the entity record for use in other checks.
func SanityCheckEntities(logger *logging.Logger, entities []*entity.SignedEntity) (map[signature.PublicKey]*entity.Entity, error) {
	seenEntities := make(map[signature.PublicKey]*entity.Entity)
	for _, sent := range entities {
		entity, err := VerifyRegisterEntityArgs(logger, sent, true)
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
	for _, srt := range runtimes {
		rt, err := VerifyRegisterRuntimeArgs(params, logger, srt, isGenesis)
		if err != nil {
			return nil, fmt.Errorf("runtime sanity check failed: %w", err)
		}
		seenRuntimes = append(seenRuntimes, rt)
	}

	seenSuspendedRuntimes := []*Runtime{}
	for _, srt := range suspendedRuntimes {
		rt, err := VerifyRegisterRuntimeArgs(params, logger, srt, isGenesis)
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
) error { // nolint: gocyclo

	nodeLookup := &sanityCheckNodeLookup{
		nodes:           make(map[signature.PublicKey]*node.Node),
		nodesCertHashes: make(map[hash.Hash]*node.Node),
	}

	for _, sn := range nodes {

		// Open the node to get the referenced entity.
		var n node.Node
		if err := sn.Open(RegisterGenesisNodeSignatureContext, &n); err != nil {
			return fmt.Errorf("registry: sanity check failed: unable to open signed node")
		}
		if !n.ID.IsValid() {
			return fmt.Errorf("registry: sanity check failed: node ID %s is invalid", n.ID.String())
		}
		entity, ok := seenEntities[n.EntityID]
		if !ok {
			return fmt.Errorf("registry: sanity check failed node: %s references a missing entity", n.ID.String())
		}

		node, _, err := VerifyRegisterNodeArgs(
			context.Background(),
			params,
			logger,
			sn,
			entity,
			time.Now(),
			isGenesis,
			epoch,
			runtimesLookup,
			nodeLookup,
		)
		if err != nil {
			return fmt.Errorf("registry: sanity check failed for node: %s, error: %w", n.ID.String(), err)
		}

		// Add validated node to nodeLookup.
		nodeLookup.nodes[node.Consensus.ID] = node
		nodeLookup.nodes[node.P2P.ID] = node

		var h = hash.Hash{}
		h.FromBytes(node.Committee.Certificate)
		nodeLookup.nodesCertHashes[h] = node
	}

	return nil
}

// Runtimes lookup used in sanity checks.
type sanityCheckRuntimeLookup struct {
	runtimes          map[common.Namespace]*Runtime
	suspendedRuntimes map[common.Namespace]*Runtime
}

func newSanityCheckRuntimeLookup(runtimes []*Runtime, suspendedRuntimes []*Runtime) (RuntimeLookup, error) {
	rtsMap := make(map[common.Namespace]*Runtime)
	sRtsMap := make(map[common.Namespace]*Runtime)
	for _, rt := range runtimes {
		if rtsMap[rt.ID] != nil {
			return nil, fmt.Errorf("duplicate runtime: %s", rt.ID)
		}
		rtsMap[rt.ID] = rt
	}
	for _, srt := range suspendedRuntimes {
		if rtsMap[srt.ID] != nil || sRtsMap[srt.ID] != nil {
			return nil, fmt.Errorf("duplicate (suspended) runtime: %s", srt.ID)
		}
		sRtsMap[srt.ID] = srt
	}
	return &sanityCheckRuntimeLookup{rtsMap, sRtsMap}, nil
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

// Node lookup used in sanity checks.
type sanityCheckNodeLookup struct {
	nodes           map[signature.PublicKey]*node.Node
	nodesCertHashes map[hash.Hash]*node.Node
}

func (n *sanityCheckNodeLookup) NodeByConsensusOrP2PKey(ctx context.Context, key signature.PublicKey) (*node.Node, error) {
	node, ok := n.nodes[key]
	if !ok {
		return nil, ErrNoSuchNode
	}
	return node, nil
}

func (n *sanityCheckNodeLookup) NodeByCertificate(ctx context.Context, cert []byte) (*node.Node, error) {
	var h = hash.Hash{}
	h.FromBytes(cert)

	node, ok := n.nodesCertHashes[h]
	if !ok {
		return nil, ErrNoSuchNode
	}
	return node, nil
}
