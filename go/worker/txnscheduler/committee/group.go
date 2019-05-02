package committee

import (
	"context"
	"sync"

	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/tracing"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/worker/p2p"
)

type epoch struct {
	roundCtx       context.Context
	cancelRoundCtx context.CancelFunc

	computeCommittee              *scheduler.Committee
	transactionSchedulerCommittee *scheduler.Committee
	computeNodes                  []*node.Node
	computeGroupHash              hash.Hash

	role scheduler.Role
}

// EpochSnapshot is an immutable snapshot of epoch state.
type EpochSnapshot struct {
	role             scheduler.Role
	computeGroupHash hash.Hash
}

// GetComputeGroupHash returns the current compute committee members hash.
func (e *EpochSnapshot) GetComputeGroupHash() hash.Hash {
	return e.computeGroupHash
}

// IsLeader checks if the current node is a leader of the transaction scheduler committee
// in the current epoch.
func (e *EpochSnapshot) IsLeader() bool {
	return e.role == scheduler.Leader
}

// Group encapsulates communication with a group of nodes in the
// compute committee.
type Group struct {
	sync.RWMutex

	identity  *identity.Identity
	runtimeID signature.PublicKey

	scheduler scheduler.Backend
	registry  registry.Backend

	activeEpoch *epoch
	p2p         *p2p.P2P

	logger *logging.Logger
}

// P2PInfo returns the information needed to establish connections to this
// node via the P2P transport.
func (g *Group) P2PInfo() node.P2PInfo {
	return g.p2p.Info()
}

// RoundTransition processes a round transition that just happened.
func (g *Group) RoundTransition(ctx context.Context) {
	g.Lock()
	defer g.Unlock()

	if g.activeEpoch == nil {
		return
	}

	(g.activeEpoch.cancelRoundCtx)()

	ctx, cancel := context.WithCancel(ctx)
	g.activeEpoch.roundCtx = ctx
	g.activeEpoch.cancelRoundCtx = cancel
}

// EpochTransition processes an epoch transition that just happened.
func (g *Group) EpochTransition(ctx context.Context, computeGroupHash hash.Hash, height int64) error {
	g.Lock()
	defer g.Unlock()

	// Cancel context for the previous epoch.
	if g.activeEpoch != nil {
		(g.activeEpoch.cancelRoundCtx)()
	}

	// Invalidate current epoch. In case we cannot process this transition,
	// this should cause the node to transition into NotReady and stay there
	// until the next epoch transition.
	g.activeEpoch = nil

	// Request committees from scheduler.
	var committees []*scheduler.Committee
	var err error
	if sched, ok := g.scheduler.(scheduler.BlockBackend); ok {
		committees, err = sched.GetBlockCommittees(ctx, g.runtimeID, height, nil)
	} else {
		committees, err = g.scheduler.GetCommittees(ctx, g.runtimeID)
	}
	if err != nil {
		return err
	}

	// Find the current compute committee.
	var computeCommittee, transactionSchedulerCommittee *scheduler.Committee
	for _, cm := range committees {
		switch cm.Kind {
		case scheduler.Compute:
			computeCommittee = cm
		case scheduler.TransactionScheduler:
			transactionSchedulerCommittee = cm
		}
	}
	if computeCommittee == nil {
		return errors.New("no compute committee")
	}
	if transactionSchedulerCommittee == nil {
		return errors.New("no transaction scheduler committee")
	}

	// Sanity check the group hash against the current committee.
	computeCommitteeHash := computeCommittee.EncodedMembersHash()
	if !computeCommitteeHash.Equal(&computeGroupHash) {
		return errors.New("received inconsistent committee")
	}

	publicIdentity := g.identity.NodeKey.Public()

	var computeNodes []*node.Node
	for _, node := range computeCommittee.Members {
		// Fetch peer node information from the registry.
		n, err := g.registry.GetNode(ctx, node.PublicKey)
		if err != nil {
			return errors.Wrap(err, "failed to fetch node info")
		}

		computeNodes = append(computeNodes, n)
	}

	// Determine our role in the transaction scheduler committee.
	var role scheduler.Role
	for _, node := range transactionSchedulerCommittee.Members {
		if node.PublicKey.Equal(publicIdentity) {
			role = node.Role
		}
	}

	// Create round context.
	roundCtx, cancel := context.WithCancel(ctx)

	// Update the current epoch.
	g.activeEpoch = &epoch{
		roundCtx,
		cancel,
		computeCommittee,
		transactionSchedulerCommittee,
		computeNodes,
		computeGroupHash,
		role,
	}

	g.logger.Info("epoch transition complete",
		"role", role,
	)

	return nil
}

// GetEpochSnapshot returns a snapshot of the currently active epoch.
func (g *Group) GetEpochSnapshot() *EpochSnapshot {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return &EpochSnapshot{role: scheduler.Invalid}
	}

	return &EpochSnapshot{
		role:             g.activeEpoch.role,
		computeGroupHash: g.activeEpoch.computeGroupHash,
	}
}

// IsPeerAuthorized returns true if a given peer should be allowed to send
// messages to us.
func (g *Group) IsPeerAuthorized(peerID []byte) bool {
	g.RLock()
	defer g.RUnlock()

	// TODO: Allow messages used for discrepancy detection.
	return false
}

// HandlePeerMessage handles an incoming message from a peer.
func (g *Group) HandlePeerMessage(peerID []byte, message p2p.Message) error {
	return errors.New("transaction scheduler messaging not implemented")
}

// PublishBatch publishes a batch to all members in the committee.
// Returns whether to publish the batch to ourselves.
func (g *Group) PublishBatch(batchSpanCtx opentracing.SpanContext, batchHash hash.Hash, hdr block.Header) (bool, error) {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.role != scheduler.Leader {
		return false, errors.New("not leader")
	}

	pubCtx := g.activeEpoch.roundCtx

	var scBinary []byte
	if batchSpanCtx != nil {
		scBinary, _ = tracing.SpanContextToBinary(batchSpanCtx)
	}

	// Publish batch to all workers in the compute committee.
	publishToSelf := false
	publicIdentity := g.identity.NodeKey.Public()
	for index, member := range g.activeEpoch.computeCommittee.Members {
		if member.Role != scheduler.Leader && member.Role != scheduler.Worker {
			continue
		}
		if member.PublicKey.Equal(publicIdentity) {
			publishToSelf = true
			continue
		}

		node := g.activeEpoch.computeNodes[index]
		g.p2p.Publish(pubCtx, node, p2p.Message{
			RuntimeID: g.runtimeID,
			GroupHash: g.activeEpoch.computeGroupHash,
			LeaderBatchDispatch: &p2p.LeaderBatchDispatch{
				BatchHash: batchHash,
				Header:    hdr,
			},
			SpanContext: scBinary,
		})
	}

	return publishToSelf, nil
}

// NewGroup creates a new group.
func NewGroup(
	identity *identity.Identity,
	runtimeID signature.PublicKey,
	registry registry.Backend,
	scheduler scheduler.Backend,
	p2p *p2p.P2P,
) (*Group, error) {
	g := &Group{
		identity:  identity,
		runtimeID: runtimeID,
		scheduler: scheduler,
		registry:  registry,
		p2p:       p2p,
		logger:    logging.GetLogger("worker/txnscheduler/committee/group").With("runtime_id", runtimeID),
	}

	p2p.RegisterHandler(runtimeID, g)

	return g, nil
}
