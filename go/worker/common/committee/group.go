package committee

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	// tagExecutor is the committee node descriptor tag to use for executor nodes.
	tagExecutor = "executor"
)

// TagForCommittee returns node lookup tag for scheduler committee kind.
func TagForCommittee(kind scheduler.CommitteeKind) string {
	switch kind {
	case scheduler.KindComputeExecutor:
		return tagExecutor
	default:
		return ""
	}
}

// CommitteeInfo contains information about a committee of nodes.
type CommitteeInfo struct {
	Indices    []int
	Roles      []scheduler.Role
	Committee  *scheduler.Committee
	PublicKeys map[signature.PublicKey]struct{}
	Peers      map[signature.PublicKey]struct{}

	nodes nodes.VersionedNodeDescriptorWatcher
}

// IsMember checks if the current node is a member of the committee.
func (ci *CommitteeInfo) IsMember() bool {
	return len(ci.Roles) > 0
}

// IsWorker checks if the current node is a worker of the committee.
func (ci *CommitteeInfo) IsWorker() bool {
	return ci.HasRole(scheduler.RoleWorker)
}

// IsBackupWorker checks if the current node is a backup worker of the committee.
func (ci *CommitteeInfo) IsBackupWorker() bool {
	return ci.HasRole(scheduler.RoleBackupWorker)
}

// HasRole checks whether the node has the given role.
func (ci *CommitteeInfo) HasRole(role scheduler.Role) bool {
	return slices.Contains(ci.Roles, role)
}

// Node looks up a node descriptor.
//
// Implements commitment.NodeLookup.
func (ci *CommitteeInfo) Node(_ context.Context, id signature.PublicKey) (*node.Node, error) {
	n := ci.nodes.Lookup(id)
	if n == nil {
		return nil, registry.ErrNoSuchNode
	}
	return n, nil
}

// Group encapsulates communication with a group of nodes in the runtime committees.
type Group struct {
	sync.RWMutex

	runtimeID common.Namespace
	identity  *identity.Identity

	consensus consensus.Service
	p2p       p2pAPI.Service

	committee *CommitteeInfo
	// nodes is a node descriptor watcher for all nodes that are part of any of our committees.
	// TODO: Consider removing nodes.
	nodes nodes.VersionedNodeDescriptorWatcher

	logger *logging.Logger
}

// NewGroup creates a new group.
func NewGroup(
	ctx context.Context,
	runtimeID common.Namespace,
	identity *identity.Identity,
	consensus consensus.Service,
	p2p p2p.Service,
) (*Group, error) {
	nw, err := nodes.NewVersionedNodeDescriptorWatcher(ctx, consensus)
	if err != nil {
		return nil, fmt.Errorf("group: failed to create node watcher: %w", err)
	}

	return &Group{
		runtimeID: runtimeID,
		identity:  identity,
		consensus: consensus,
		p2p:       p2p,
		nodes:     nw,
		logger:    logging.GetLogger("worker/common/committee/group").With("runtime_id", runtimeID),
	}, nil
}

// CommitteeInfo returns the currently active committee info.
func (g *Group) CommitteeInfo() (*CommitteeInfo, bool) {
	g.RLock()
	defer g.RUnlock()

	if g.committee == nil {
		return nil, false
	}

	return g.committee, true
}

// Suspend processes a runtime suspension that just happened.
//
// Resumption will be processed as a regular epoch transition.
func (g *Group) Suspend() {
	g.Lock()
	defer g.Unlock()

	// Invalidate current committee.
	g.committee = nil
}

// CommitteeTransition processes a committee transition that just happened.
func (g *Group) CommitteeTransition(ctx context.Context, committee *scheduler.Committee) error {
	g.Lock()
	defer g.Unlock()

	g.logger.Info("committee transition")

	// Invalidate current committee. In case we cannot process this transition,
	// this should cause the node to transition into NotReady and stay there
	// until the next epoch transition.
	g.committee = nil
	// Reset watched nodes.
	g.nodes.Reset()
	defer func() {
		// Make sure there are no unneeded watched nodes in case this method fails.
		if g.committee == nil {
			g.nodes.Reset()
		}
	}()

	// Find the current committees.
	publicIdentity := g.identity.NodeSigner.Public()

	var (
		roles   []scheduler.Role
		indices []int
	)
	publicKeys := make(map[signature.PublicKey]struct{})
	peers := make(map[signature.PublicKey]struct{})
	for index, member := range committee.Members {
		publicKeys[member.PublicKey] = struct{}{}
		if member.PublicKey.Equal(publicIdentity) {
			roles = append(roles, member.Role)
			indices = append(indices, index)
		}

		// Start watching the member's node descriptor.
		n, err := g.nodes.WatchNodeWithTag(ctx, member.PublicKey, TagForCommittee(committee.Kind))
		if err != nil {
			return fmt.Errorf("group: failed to fetch node info: %w", err)
		}

		peers[n.P2P.ID] = struct{}{}
	}

	// Freeze the committee.
	g.nodes.Freeze(0)

	// Mark all executor nodes in the current committee as important.
	if pm := g.p2p.PeerManager(); pm != nil {
		if pids, err := p2p.PublicKeyMapToPeerIDs(peers); err == nil {
			pm.PeerTagger().SetPeerImportance(p2p.ImportantNodeCompute, g.runtimeID, pids)
		}
	}

	// Update the current committee.
	g.committee = &CommitteeInfo{
		Indices:    indices,
		Roles:      roles,
		Committee:  committee,
		PublicKeys: publicKeys,
		Peers:      peers,
		nodes:      g.nodes,
	}

	g.logger.Info("committee transition complete",
		"epoch", epochNumber,
		"executor_roles", g.committee.Roles,
	)

	return nil
}
