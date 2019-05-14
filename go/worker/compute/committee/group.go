package committee

import (
	"bytes"
	"context"
	"sync"

	"github.com/opentracing/opentracing-go"
	opentracingExt "github.com/opentracing/opentracing-go/ext"
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crash"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/tracing"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/worker/compute/p2p"
)

// BatchHandler is a handler for batches incoming from other members
// of the compute committee, originated by the leader node.
type BatchHandler interface {
	// HandleBatchFromCommittee processes an incoming batch.
	//
	// The call has already been authenticated to come from a committee
	// member.
	//
	// The batch identifier is a hash of the batch which can be used
	// to retrieve the batch from storage.
	//
	// The block header determines what block the batch should be
	// computed against.
	HandleBatchFromCommittee(ctx context.Context, batchHash hash.Hash, hdr block.Header) error
}

type epoch struct {
	roundCtx       context.Context
	cancelRoundCtx context.CancelFunc

	computeCommittee              *scheduler.Committee
	transactionSchedulerCommittee *scheduler.Committee
	nodes                         []*node.Node
	groupHash                     hash.Hash
	// The transaction scheduler leader's peer ID.
	leaderPeerID []byte

	computeRole              scheduler.Role
	transactionSchedulerRole scheduler.Role
}

// EpochSnapshot is an immutable snapshot of epoch state.
type EpochSnapshot struct {
	computeRole              scheduler.Role
	transactionSchedulerRole scheduler.Role
	groupHash                hash.Hash
}

// GetGroupHash returns the current committee members hash.
func (e *EpochSnapshot) GetGroupHash() hash.Hash {
	return e.groupHash
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
	return e.transactionSchedulerRole == scheduler.Leader
}

// Group encapsulates communication with a group of nodes in the
// compute committee.
type Group struct {
	sync.RWMutex

	identity  *identity.Identity
	runtimeID signature.PublicKey

	scheduler scheduler.Backend
	registry  registry.Backend

	handler BatchHandler

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
func (g *Group) EpochTransition(ctx context.Context, groupHash hash.Hash, height int64) error {
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
	committeeHash := computeCommittee.EncodedMembersHash()
	if !committeeHash.Equal(&groupHash) {
		return errors.New("received inconsistent committee")
	}

	publicIdentity := g.identity.NodeKey.Public()

	// Determine our role in the compute committee.
	var nodes []*node.Node
	var computeRole scheduler.Role
	for _, node := range computeCommittee.Members {
		if node.PublicKey.Equal(publicIdentity) {
			computeRole = node.Role
			// Use nil for our own node to not break indices.
			nodes = append(nodes, nil)
		} else {
			// Fetch peer node information from the registry.
			n, err := g.registry.GetNode(ctx, node.PublicKey)
			if err != nil {
				return errors.Wrap(err, "failed to fetch node info")
			}

			nodes = append(nodes, n)
		}
	}

	// Determine our role in the transaction scheduler committee.
	var transactionSchedulerRole scheduler.Role
	var leaderPeerID []byte
	for _, node := range transactionSchedulerCommittee.Members {
		if node.PublicKey.Equal(publicIdentity) {
			transactionSchedulerRole = node.Role
		} else if node.Role == scheduler.Leader {
			// Fetch peer node information from the registry.
			n, err := g.registry.GetNode(ctx, node.PublicKey)
			if err != nil {
				return errors.Wrap(err, "failed to fetch node info")
			}
			leaderPeerID = n.P2P.ID
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
		nodes,
		groupHash,
		leaderPeerID,
		computeRole,
		transactionSchedulerRole,
	}

	g.logger.Info("epoch transition complete",
		"computeRole", computeRole,
		"transactionSchedulerRole", transactionSchedulerRole,
	)

	return nil
}

// GetEpochSnapshot returns a snapshot of the currently active epoch.
func (g *Group) GetEpochSnapshot() *EpochSnapshot {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return &EpochSnapshot{computeRole: scheduler.Invalid, transactionSchedulerRole: scheduler.Invalid}
	}

	return &EpochSnapshot{
		computeRole:              g.activeEpoch.computeRole,
		transactionSchedulerRole: g.activeEpoch.transactionSchedulerRole,
		groupHash:                g.activeEpoch.groupHash,
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

	// Currently we only accept messages from the transaction scheduler committee leader.
	return g.activeEpoch.leaderPeerID != nil && bytes.Equal(peerID, g.activeEpoch.leaderPeerID)
}

// HandlePeerMessage handles an incoming message from a peer.
func (g *Group) HandlePeerMessage(peerID []byte, message p2p.Message) error {
	// Perform some checks on the incoming message. We make sure to release the
	// lock before running the handler.
	ctx, err := func() (context.Context, error) {
		g.RLock()
		defer g.RUnlock()

		// Ensure that we are a worker as currently the only allowed communication
		// is the leader sending batches to workers.
		if g.activeEpoch == nil || g.activeEpoch.computeRole != scheduler.Leader && g.activeEpoch.computeRole != scheduler.Worker {
			return nil, errors.New("not compute leader or worker")
		}

		if g.activeEpoch.leaderPeerID == nil || !bytes.Equal(peerID, g.activeEpoch.leaderPeerID) {
			// Currently we only accept messages from the transaction scheduler committee leader.
			return nil, errors.New("peer is not transaction scheduler leader")
		}

		// Ensure that both peers have the same view of the current group. If this
		// is not the case, this means that one of the nodes processed an epoch
		// transition and the other one didn't.
		if !message.GroupHash.Equal(&g.activeEpoch.groupHash) {
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

	if message.LeaderBatchDispatch != nil {
		bd := message.LeaderBatchDispatch
		return g.handler.HandleBatchFromCommittee(ctx, bd.BatchHash, bd.Header)
	}

	return errors.New("unknown message type")
}

// PublishBatch publishes a batch to all members in the committee.
func (g *Group) PublishBatch(batchSpanCtx opentracing.SpanContext, batchHash hash.Hash, hdr block.Header) error {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.transactionSchedulerRole != scheduler.Leader {
		return errors.New("not leader")
	}

	pubCtx := g.activeEpoch.roundCtx

	var scBinary []byte
	if batchSpanCtx != nil {
		scBinary, _ = tracing.SpanContextToBinary(batchSpanCtx)
	}

	// Publish batch to all workers in the compute committee.
	publicIdentity := g.identity.NodeKey.Public()
	for index, member := range g.activeEpoch.computeCommittee.Members {
		if member.Role != scheduler.Leader && member.Role != scheduler.Worker {
			continue
		}
		if member.PublicKey.Equal(publicIdentity) {
			// Skip self, because we don't keep our own P2P address and because
			// we'll start it locally after this.
			continue
		}

		node := g.activeEpoch.nodes[index]
		g.p2p.Publish(pubCtx, node, p2p.Message{
			RuntimeID: g.runtimeID,
			GroupHash: g.activeEpoch.groupHash,
			LeaderBatchDispatch: &p2p.LeaderBatchDispatch{
				BatchHash: batchHash,
				Header:    hdr,
			},
			SpanContext: scBinary,
		})
	}
	crash.Here(crashPointLeaderBatchPublishAfter)

	return nil
}

// NewGroup creates a new group.
func NewGroup(
	identity *identity.Identity,
	runtimeID signature.PublicKey,
	handler BatchHandler,
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
		logger:    logging.GetLogger("worker/compute/committee/group").With("runtime_id", runtimeID),
	}

	p2p.RegisterHandler(runtimeID, g)

	return g, nil
}
