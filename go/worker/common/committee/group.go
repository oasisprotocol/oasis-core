package committee

import (
	"bytes"
	"context"
	"sync"

	"github.com/opentracing/opentracing-go"
	opentracingExt "github.com/opentracing/opentracing-go/ext"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/common/tracing"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
)

// MessageHandler handles messages from other nodes.
type MessageHandler interface {
	// HandlePeerMessage handles a message.
	//
	// The message has already been authenticated to come from a registered node.
	HandlePeerMessage(ctx context.Context, message *p2p.Message) error
}

type epoch struct {
	roundCtx       context.Context
	cancelRoundCtx context.CancelFunc

	computeCommitteeID hash.Hash
	computeCommittee   *scheduler.Committee
	computeNodes       []*node.Node

	txnSchedulerCommittee    *scheduler.Committee
	txnSchedulerLeaderPeerID []byte

	mergeCommittee *scheduler.Committee
	mergeNodes     []*node.Node

	runtime *registry.Runtime

	// Keep these at the end for struct packing.
	computeRole      scheduler.Role
	txnSchedulerRole scheduler.Role
	mergeRole        scheduler.Role
}

// EpochSnapshot is an immutable snapshot of epoch state.
type EpochSnapshot struct {
	computeCommitteeID hash.Hash

	computeRole      scheduler.Role
	txnSchedulerRole scheduler.Role
	mergeRole        scheduler.Role

	runtime *registry.Runtime

	computeCommittee *scheduler.Committee
	computeNodes     []*node.Node
}

// GetRuntime returns the current runtime descriptor.
func (e *EpochSnapshot) GetRuntime() *registry.Runtime {
	return e.runtime
}

// GetComputeCommittee returns the current compute committee.
func (e *EpochSnapshot) GetComputeCommittee() *scheduler.Committee {
	return e.computeCommittee
}

// GetComputeCommitteeID returns the current committee members hash.
func (e *EpochSnapshot) GetComputeCommitteeID() hash.Hash {
	return e.computeCommitteeID
}

// GetComputeNodes returns the nodes in the current compute committee.
func (e *EpochSnapshot) GetComputeNodes() []*node.Node {
	return e.computeNodes
}

// IsComputeMember checks if the current node is a member of the compute committee
// in the current epoch.
func (e *EpochSnapshot) IsComputeMember() bool {
	return e.computeRole != scheduler.Invalid
}

// IsComputeLeader checks if the current node is a leader of the compute committee
// in the current epoch.
func (e *EpochSnapshot) IsComputeLeader() bool {
	return e.computeRole == scheduler.Leader
}

// IsComputeWorker checks if the current node is a worker of the compute committee
// in the current epoch.
func (e *EpochSnapshot) IsComputeWorker() bool {
	return e.computeRole == scheduler.Worker
}

// IsComputeBackupWorker checks if the current node is a backup worker of the compute
// committee in the current epoch.
func (e *EpochSnapshot) IsComputeBackupWorker() bool {
	return e.computeRole == scheduler.BackupWorker
}

// IsTransactionSchedulerLeader checks if the current node is a leader of the transaction scheduler committee
// in the current epoch.
func (e *EpochSnapshot) IsTransactionSchedulerLeader() bool {
	return e.txnSchedulerRole == scheduler.Leader
}

// IsMergeMember checks if the current node is a member of the merge committee
// in the current epoch.
func (e *EpochSnapshot) IsMergeMember() bool {
	return e.mergeRole != scheduler.Invalid
}

// IsMergeWorker checks if the current node is a worker of the merge committee in
// the current epoch.
func (e *EpochSnapshot) IsMergeWorker() bool {
	// TODO: Leader is ignored so it can easily be removed once we get rid of leaders.
	return e.mergeRole == scheduler.Leader || e.mergeRole == scheduler.Worker
}

// IsMergeBackupWorker checks if the current node is a backup worker of the merge committee in
// the current epoch.
func (e *EpochSnapshot) IsMergeBackupWorker() bool {
	return e.mergeRole == scheduler.BackupWorker
}

// Group encapsulates communication with a group of nodes in the
// compute committee.
type Group struct {
	sync.RWMutex

	identity  *identity.Identity
	runtimeID signature.PublicKey

	scheduler scheduler.Backend
	registry  registry.Backend

	handler MessageHandler

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
func (g *Group) EpochTransition(ctx context.Context, height int64) error {
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

	// Find the current committees.
	var computeCommittee, txnSchedulerCommittee, mergeCommittee *scheduler.Committee
	for _, cm := range committees {
		switch cm.Kind {
		case scheduler.Compute:
			computeCommittee = cm
		case scheduler.TransactionScheduler:
			txnSchedulerCommittee = cm
		case scheduler.Merge:
			mergeCommittee = cm
		}
	}
	if computeCommittee == nil {
		return errors.New("no compute committee")
	}
	if txnSchedulerCommittee == nil {
		return errors.New("no transaction scheduler committee")
	}
	if mergeCommittee == nil {
		return errors.New("no merge committee")
	}

	computeCommitteeID := computeCommittee.EncodedMembersHash()

	publicIdentity := g.identity.NodeKey.Public()

	determineRole := func(c *scheduler.Committee) (nodes []*node.Node, leader int, role scheduler.Role, err error) {
		leader = -1

		for idx, node := range c.Members {
			if node.PublicKey.Equal(publicIdentity) {
				role = node.Role
			}

			// Fetch peer node information from the registry.
			n, err := g.registry.GetNode(ctx, node.PublicKey)
			if err != nil {
				return nil, -1, scheduler.Invalid, errors.Wrap(err, "failed to fetch node info")
			}

			nodes = append(nodes, n)

			if node.Role == scheduler.Leader {
				leader = idx
			}
		}
		return
	}

	// Determine our role in the compute committee.
	computeNodes, _, computeRole, err := determineRole(computeCommittee)
	if err != nil {
		return err
	}

	// Determine our role in the transaction scheduler committee.
	txnSchedulerNodes, leader, txnSchedulerRole, err := determineRole(txnSchedulerCommittee)
	if err != nil {
		return err
	}

	var txnSchedulerLeaderPeerID []byte
	if leader != -1 {
		txnSchedulerLeaderPeerID = txnSchedulerNodes[leader].P2P.ID
	}

	// Determine our role in the merge committee.
	mergeNodes, _, mergeRole, err := determineRole(mergeCommittee)
	if err != nil {
		return err
	}

	// Fetch current runtime descriptor.
	runtime, err := g.registry.GetRuntime(ctx, g.runtimeID)
	if err != nil {
		return err
	}

	// Create round context.
	roundCtx, cancel := context.WithCancel(ctx)

	// Update the current epoch.
	g.activeEpoch = &epoch{
		roundCtx,
		cancel,
		computeCommitteeID,
		computeCommittee,
		computeNodes,
		txnSchedulerCommittee,
		txnSchedulerLeaderPeerID,
		mergeCommittee,
		mergeNodes,
		runtime,
		computeRole,
		txnSchedulerRole,
		mergeRole,
	}

	g.logger.Info("epoch transition complete",
		"compute_role", computeRole,
		"transaction_scheduler_role", txnSchedulerRole,
		"merge_role", mergeRole,
	)

	return nil
}

// GetEpochSnapshot returns a snapshot of the currently active epoch.
func (g *Group) GetEpochSnapshot() *EpochSnapshot {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return &EpochSnapshot{
			computeRole:      scheduler.Invalid,
			txnSchedulerRole: scheduler.Invalid,
			mergeRole:        scheduler.Invalid,
		}
	}

	return &EpochSnapshot{
		computeRole:        g.activeEpoch.computeRole,
		computeCommitteeID: g.activeEpoch.computeCommitteeID,
		txnSchedulerRole:   g.activeEpoch.txnSchedulerRole,
		mergeRole:          g.activeEpoch.mergeRole,
		runtime:            g.activeEpoch.runtime,
		computeCommittee:   g.activeEpoch.computeCommittee,
		computeNodes:       g.activeEpoch.computeNodes,
	}
}

// IsPeerAuthorized returns true if a given peer should be allowed to send
// messages to us.
func (g *Group) IsPeerAuthorized(peerID []byte) bool {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return false
	}

	// Assume the peer is not authorized.
	var authorized bool

	// If we are in the compute committee, we accept messages from the transaction
	// scheduler committee leader.
	if g.activeEpoch.computeRole != scheduler.Invalid && g.activeEpoch.txnSchedulerLeaderPeerID != nil {
		authorized = authorized || bytes.Equal(peerID, g.activeEpoch.txnSchedulerLeaderPeerID)
	}

	// If we are in the merge committee, we accept messages from the compute committee.
	if g.activeEpoch.mergeRole != scheduler.Invalid {
		for _, n := range g.activeEpoch.computeNodes {
			if n == nil {
				continue
			}

			if bytes.Equal(peerID, n.P2P.ID) {
				authorized = true
				break
			}
		}
	}

	return authorized
}

// HandlePeerMessage handles an incoming message from a peer.
func (g *Group) HandlePeerMessage(peerID []byte, message *p2p.Message) error {
	// Perform some checks on the incoming message. We make sure to release the
	// lock before running the handler.
	ctx, err := func() (context.Context, error) {
		g.RLock()
		defer g.RUnlock()

		// Ensure that both peers have the same view of the current group. If this
		// is not the case, this means that one of the nodes processed an epoch
		// transition and the other one didn't.
		if !message.GroupHash.Equal(&g.activeEpoch.computeCommitteeID) {
			return nil, errors.New("message is not for the current group")
		}

		return g.activeEpoch.roundCtx, nil
	}()
	if err != nil {
		return err
	}

	// Import SpanContext from the message and store it in the current Context.
	if message.SpanContext != nil {
		sc, err := tracing.SpanContextFromBinary(message.SpanContext)
		if err == nil {
			parentSpan := opentracing.StartSpan("parent", opentracingExt.RPCServerOption(sc))
			span := opentracing.StartSpan("HandleBatch", opentracing.FollowsFrom(parentSpan.Context()))
			defer span.Finish()
			ctx = opentracing.ContextWithSpan(ctx, span)
		}
	}

	return g.handler.HandlePeerMessage(ctx, message)
}

func (g *Group) publishLocked(
	spanCtx opentracing.SpanContext,
	c *scheduler.Committee,
	nodes []*node.Node,
	filter func(*scheduler.CommitteeNode) bool,
	msg *p2p.Message,
) error {
	pubCtx := g.activeEpoch.roundCtx

	var scBinary []byte
	if spanCtx != nil {
		scBinary, _ = tracing.SpanContextToBinary(spanCtx)
	}

	// Populate message fields.
	msg.RuntimeID = g.runtimeID
	msg.GroupHash = g.activeEpoch.computeCommitteeID
	msg.SpanContext = scBinary

	// Publish batch to given committee.
	publicIdentity := g.identity.NodeKey.Public()
	for index, member := range c.Members {
		if !filter(member) {
			continue
		}
		if member.PublicKey.Equal(publicIdentity) {
			// Do not publish to self.
			continue
		}

		g.p2p.Publish(pubCtx, nodes[index], msg)
	}

	return nil
}

// PublishScheduledBatch publishes a batch to all members in the compute committee.
func (g *Group) PublishScheduledBatch(spanCtx opentracing.SpanContext, batch runtime.Batch, hdr block.Header) error {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.txnSchedulerRole != scheduler.Leader {
		return errors.New("not leader")
	}

	return g.publishLocked(
		spanCtx,
		g.activeEpoch.computeCommittee,
		g.activeEpoch.computeNodes,
		// Publish to all committee members.
		func(n *scheduler.CommitteeNode) bool { return true },
		&p2p.Message{
			LeaderBatchDispatch: &p2p.LeaderBatchDispatch{
				Batch:  batch,
				Header: hdr,
			},
		},
	)
}

func (g *Group) PublishComputeFinished(spanCtx opentracing.SpanContext, c *commitment.ComputeCommitment) error {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.computeRole == scheduler.Invalid {
		return errors.New("not member")
	}

	return g.publishLocked(
		spanCtx,
		g.activeEpoch.mergeCommittee,
		g.activeEpoch.mergeNodes,
		// Publish to all committee members.
		func(n *scheduler.CommitteeNode) bool { return true },
		&p2p.Message{
			ComputeWorkerFinished: &p2p.ComputeWorkerFinished{
				Commitment: *c,
			},
		},
	)
}

// NewGroup creates a new group.
func NewGroup(
	identity *identity.Identity,
	runtimeID signature.PublicKey,
	handler MessageHandler,
	registry registry.Backend,
	scheduler scheduler.Backend,
	p2p *p2p.P2P,
) (*Group, error) {
	g := &Group{
		identity:  identity,
		runtimeID: runtimeID,
		scheduler: scheduler,
		registry:  registry,
		handler:   handler,
		p2p:       p2p,
		logger:    logging.GetLogger("worker/common/committee/group").With("runtime_id", runtimeID),
	}

	p2p.RegisterHandler(runtimeID, g)

	return g, nil
}
