package committee

import (
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

// CommitteeInfo contains information about a committee of nodes.
type CommitteeInfo struct { // nolint: golint
	Role      scheduler.Role
	Committee *scheduler.Committee
	Nodes     []*node.Node
}

type epoch struct {
	roundCtx       context.Context
	cancelRoundCtx context.CancelFunc

	// groupVersion is the consensus backend block height of the last processed
	// committee election.
	groupVersion int64

	// computeCommittee is the compute committee we are a member of.
	computeCommittee *CommitteeInfo
	// computeCommitteeID is the identifier of our compute committee.
	computeCommitteeID hash.Hash
	// computeCommittees are all compute committees.
	computeCommittees map[hash.Hash]*CommitteeInfo
	// computeCommitteesByPeer is a set of P2P public keys of compute committee
	// members.
	computeCommitteesByPeer map[signature.MapKey]bool

	// txnSchedulerCommitee is the txn scheduler committee we are a member of.
	txnSchedulerCommittee *CommitteeInfo
	// txnSchedulerLeaderPeerID is the P2P public key of txn scheduler leader.
	txnSchedulerLeaderPeerID signature.PublicKey

	// mergeCommittee is the merge committee we are a member of.
	mergeCommittee *CommitteeInfo

	runtime *registry.Runtime
}

// EpochSnapshot is an immutable snapshot of epoch state.
type EpochSnapshot struct {
	computeCommitteeID hash.Hash

	computeRole      scheduler.Role
	txnSchedulerRole scheduler.Role
	mergeRole        scheduler.Role

	runtime *registry.Runtime

	computeCommittees map[hash.Hash]*CommitteeInfo
}

// GetRuntime returns the current runtime descriptor.
func (e *EpochSnapshot) GetRuntime() *registry.Runtime {
	return e.runtime
}

// GetComputeCommittees returns the current compute committees.
func (e *EpochSnapshot) GetComputeCommittees() map[hash.Hash]*CommitteeInfo {
	return e.computeCommittees
}

// GetComputeCommitteeID returns ID of the compute committee the current node is
// a member of.
//
// NOTE: Will return an invalid all-zero ID if not a member.
func (e *EpochSnapshot) GetComputeCommitteeID() hash.Hash {
	return e.computeCommitteeID
}

// IsComputeMember checks if the current node is a member of the compute committee
// in the current epoch.
func (e *EpochSnapshot) IsComputeMember() bool {
	return e.computeRole != scheduler.Invalid
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
	return e.mergeRole == scheduler.Worker
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
	committees, err = g.scheduler.GetCommittees(ctx, g.runtimeID, height)
	if err != nil {
		return err
	}

	publicIdentity := g.identity.NodeSigner.Public()

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

	// Find the current committees.
	computeCommittees := make(map[hash.Hash]*CommitteeInfo)
	computeCommitteesByPeer := make(map[signature.MapKey]bool)
	var computeCommittee, txnSchedulerCommittee, mergeCommittee *CommitteeInfo
	var computeCommitteeID hash.Hash
	var txnSchedulerLeaderPeerID signature.PublicKey
	for _, cm := range committees {
		nodes, leader, role, rerr := determineRole(cm)
		if rerr != nil {
			return rerr
		}

		ci := &CommitteeInfo{
			Role:      role,
			Committee: cm,
			Nodes:     nodes,
		}

		switch cm.Kind {
		case scheduler.KindCompute:
			// There can be multiple compute committees per runtime.
			cID := cm.EncodedMembersHash()
			computeCommittees[cID] = ci
			if role != scheduler.Invalid {
				if computeCommittee != nil {
					return errors.New("member of multiple compute committees")
				}

				computeCommittee = ci
				computeCommitteeID = cID
			}

			for _, n := range nodes {
				computeCommitteesByPeer[n.P2P.ID.ToMapKey()] = true
			}
		case scheduler.KindTransactionScheduler:
			txnSchedulerCommittee = ci
			if leader != -1 {
				txnSchedulerLeaderPeerID = nodes[leader].P2P.ID
			}
		case scheduler.KindMerge:
			mergeCommittee = ci
		}
	}
	if len(computeCommittees) == 0 {
		return errors.New("no compute committees")
	}
	if txnSchedulerCommittee == nil {
		return errors.New("no transaction scheduler committee")
	}
	if mergeCommittee == nil {
		return errors.New("no merge committee")
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
		height,
		computeCommittee,
		computeCommitteeID,
		computeCommittees,
		computeCommitteesByPeer,
		txnSchedulerCommittee,
		txnSchedulerLeaderPeerID,
		mergeCommittee,
		runtime,
	}

	// Compute committee may be nil in case we are not a member of any committee.
	var computeRole scheduler.Role
	if computeCommittee != nil {
		computeRole = computeCommittee.Role
	}

	g.logger.Info("epoch transition complete",
		"group_version", height,
		"compute_role", computeRole,
		"transaction_scheduler_role", txnSchedulerCommittee.Role,
		"merge_role", mergeCommittee.Role,
	)

	return nil
}

// GetEpochSnapshot returns a snapshot of the currently active epoch.
func (g *Group) GetEpochSnapshot() *EpochSnapshot {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return &EpochSnapshot{}
	}

	s := &EpochSnapshot{
		// NOTE: Transaction scheduler and merge committees are always set.
		txnSchedulerRole:  g.activeEpoch.txnSchedulerCommittee.Role,
		mergeRole:         g.activeEpoch.mergeCommittee.Role,
		runtime:           g.activeEpoch.runtime,
		computeCommittees: g.activeEpoch.computeCommittees,
	}

	// Compute committee may be nil in case we are not a member of any committee.
	cc := g.activeEpoch.computeCommittee
	if cc != nil {
		s.computeRole = cc.Role
		s.computeCommitteeID = g.activeEpoch.computeCommitteeID
	}

	return s
}

// IsPeerAuthorized returns true if a given peer should be allowed to send
// messages to us.
func (g *Group) IsPeerAuthorized(peerID signature.PublicKey) bool {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return false
	}

	// Assume the peer is not authorized.
	var authorized bool

	// If we are in the compute committee, we accept messages from the transaction
	// scheduler committee leader.
	if g.activeEpoch.computeCommittee != nil && g.activeEpoch.txnSchedulerLeaderPeerID != nil {
		authorized = authorized || peerID.Equal(g.activeEpoch.txnSchedulerLeaderPeerID)
	}

	// If we are in the merge committee, we accept messages from any compute committee member.
	if g.activeEpoch.mergeCommittee.Role != scheduler.Invalid {
		_, ok := g.activeEpoch.computeCommitteesByPeer[peerID.ToMapKey()]
		authorized = authorized || ok
	}

	return authorized
}

// HandlePeerMessage handles an incoming message from a peer.
func (g *Group) HandlePeerMessage(unusedPeerID signature.PublicKey, message *p2p.Message) error {
	// Perform some checks on the incoming message. We make sure to release the
	// lock before running the handler.
	ctx, err := func() (context.Context, error) {
		g.RLock()
		defer g.RUnlock()

		// Ensure that both peers have the same view of the current group. If this
		// is not the case, this means that one of the nodes processed an epoch
		// transition and the other one didn't.
		if message.GroupVersion != g.activeEpoch.groupVersion {
			return nil, errors.New("group version mismatch")
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
	ci *CommitteeInfo,
	msg *p2p.Message,
) error {
	pubCtx := g.activeEpoch.roundCtx

	var scBinary []byte
	if spanCtx != nil {
		scBinary, _ = tracing.SpanContextToBinary(spanCtx)
	}

	// Populate message fields.
	msg.RuntimeID = g.runtimeID
	msg.GroupVersion = g.activeEpoch.groupVersion
	msg.SpanContext = scBinary

	// Publish batch to given committee.
	publicIdentity := g.identity.NodeSigner.Public()
	for index, member := range ci.Committee.Members {
		if member.PublicKey.Equal(publicIdentity) {
			// Do not publish to self.
			continue
		}

		g.p2p.Publish(pubCtx, ci.Nodes[index], msg)
	}

	return nil
}

// PublishScheduledBatch publishes a batch to all members in the compute committee.
func (g *Group) PublishScheduledBatch(
	spanCtx opentracing.SpanContext,
	committeeID hash.Hash,
	ioRoot hash.Hash,
	storageSignatures []signature.Signature,
	hdr block.Header,
) error {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.txnSchedulerCommittee.Role != scheduler.Leader {
		return errors.New("group: not leader of txn scheduler committee")
	}

	cc := g.activeEpoch.computeCommittees[committeeID]
	if cc == nil {
		return errors.New("group: invalid compute committee")
	}

	return g.publishLocked(
		spanCtx,
		cc,
		&p2p.Message{
			TxnSchedulerBatchDispatch: &p2p.TxnSchedulerBatchDispatch{
				CommitteeID:       committeeID,
				IORoot:            ioRoot,
				StorageSignatures: storageSignatures,
				Header:            hdr,
			},
		},
	)
}

// PublishComputeFinished publishes a compute commitment to all members in the merge
// committee.
func (g *Group) PublishComputeFinished(spanCtx opentracing.SpanContext, c *commitment.ComputeCommitment) error {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.computeCommittee == nil {
		return errors.New("group: not member of compute committee")
	}

	return g.publishLocked(
		spanCtx,
		g.activeEpoch.mergeCommittee,
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
