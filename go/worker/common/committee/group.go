package committee

import (
	"context"
	"fmt"
	"sync"

	"github.com/opentracing/opentracing-go"
	opentracingExt "github.com/opentracing/opentracing-go/ext"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/tracing"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/epochtime/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	"github.com/oasislabs/oasis-core/go/runtime/committee"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
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
	Role       scheduler.Role
	Committee  *scheduler.Committee
	PublicKeys map[signature.PublicKey]bool
}

type epoch struct {
	epochCtx       context.Context
	cancelEpochCtx context.CancelFunc
	roundCtx       context.Context
	cancelRoundCtx context.CancelFunc

	// groupVersion is the consensus backend block height of the last processed
	// committee election.
	groupVersion int64

	// epochNumber is the sequential number of the epoch.
	epochNumber api.EpochTime

	// executorCommittee is the executor committee we are a member of.
	executorCommittee *CommitteeInfo
	// executorCommitteeID is the identifier of our executor committee.
	executorCommitteeID hash.Hash
	// executorCommittees are all executor committees.
	executorCommittees map[hash.Hash]*CommitteeInfo
	// executorCommitteeMemberSet is a set of node public keys of executor committee members.
	executorCommitteeMemberSet map[signature.PublicKey]bool

	// txnSchedulerCommitee is the txn scheduler committee we are a member of.
	txnSchedulerCommittee *CommitteeInfo
	// txnSchedulerLeader is the node public key of txn scheduler leader.
	txnSchedulerLeader signature.PublicKey

	// mergeCommittee is the merge committee we are a member of.
	mergeCommittee *CommitteeInfo

	// storageCommittee is the storage committee we are a member of.
	storageCommittee *CommitteeInfo

	runtime *registry.Runtime
}

// EpochSnapshot is an immutable snapshot of epoch state.
type EpochSnapshot struct {
	groupVersion int64

	executorCommitteeID hash.Hash

	epochNumber api.EpochTime

	executorRole     scheduler.Role
	txnSchedulerRole scheduler.Role
	mergeRole        scheduler.Role

	runtime *registry.Runtime

	executorCommittees    map[hash.Hash]*CommitteeInfo
	txnSchedulerCommittee *CommitteeInfo
	mergeCommittee        *CommitteeInfo
	storageCommittee      *CommitteeInfo

	nodes committee.NodeDescriptorLookup
}

// NewMockEpochSnapshot returns a mock epoch snapshot to be used in tests.
func NewMockEpochSnapshot() *EpochSnapshot {
	var executorCommitteeID hash.Hash
	executorCommitteeID.FromBytes([]byte("mock committee id"))

	return &EpochSnapshot{
		executorCommitteeID: executorCommitteeID,
		executorCommittees: map[hash.Hash]*CommitteeInfo{
			executorCommitteeID: &CommitteeInfo{},
		},
	}
}

// GetGroupVersion returns the consensus backend block height of the last
// processed committee election.
func (e *EpochSnapshot) GetGroupVersion() int64 {
	return e.groupVersion
}

// GetRuntime returns the current runtime descriptor.
func (e *EpochSnapshot) GetRuntime() *registry.Runtime {
	return e.runtime
}

// GetExecutorCommittees returns the current executor committees.
func (e *EpochSnapshot) GetExecutorCommittees() map[hash.Hash]*CommitteeInfo {
	return e.executorCommittees
}

// GetExecutorCommitteeID returns ID of the executor committee the current node is
// a member of.
//
// NOTE: Will return an invalid all-zero ID if not a member.
func (e *EpochSnapshot) GetExecutorCommitteeID() hash.Hash {
	return e.executorCommitteeID
}

// GetEpochNumber returns the sequential number of the epoch.
func (e *EpochSnapshot) GetEpochNumber() api.EpochTime {
	return e.epochNumber
}

// IsExecutorMember checks if the current node is a member of the executor committee
// in the current epoch.
func (e *EpochSnapshot) IsExecutorMember() bool {
	return e.executorRole != scheduler.Invalid
}

// IsExecutorWorker checks if the current node is a worker of the executor committee
// in the current epoch.
func (e *EpochSnapshot) IsExecutorWorker() bool {
	return e.executorRole == scheduler.Worker
}

// IsExecutorBackupWorker checks if the current node is a backup worker of the executor
// committee in the current epoch.
func (e *EpochSnapshot) IsExecutorBackupWorker() bool {
	return e.executorRole == scheduler.BackupWorker
}

// GetTransactionSchedulerCommittee returns the current txn scheduler committee.
func (e *EpochSnapshot) GetTransactionSchedulerCommittee() *CommitteeInfo {
	return e.txnSchedulerCommittee
}

// IsTransactionSchedulerLeader checks if the current node is a leader of the transaction scheduler committee
// in the current epoch.
func (e *EpochSnapshot) IsTransactionSchedulerLeader() bool {
	return e.txnSchedulerRole == scheduler.Leader
}

// GetMergeCommittee returns the current merge committee.
func (e *EpochSnapshot) GetMergeCommittee() *CommitteeInfo {
	return e.mergeCommittee
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

// GetStorageCommittee returns the current storage committee.
func (e *EpochSnapshot) GetStorageCommittee() *CommitteeInfo {
	return e.storageCommittee
}

// Nodes returns a node descriptor lookup interface.
func (e *EpochSnapshot) Nodes() committee.NodeDescriptorLookup {
	return e.nodes
}

// Node looks up a node descriptor.
//
// Implements commitment.NodeLookup.
func (e *EpochSnapshot) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	n := e.nodes.Lookup(id)
	if n == nil {
		return nil, registry.ErrNoSuchNode
	}
	return n, nil
}

// VerifyCommitteeSignatures verifies that the given signatures come from
// the current committee members of the given kind.
//
// Implements commitment.SignatureVerifier.
func (e *EpochSnapshot) VerifyCommitteeSignatures(kind scheduler.CommitteeKind, sigs []signature.Signature) error {
	var committee *CommitteeInfo
	switch kind {
	case scheduler.KindStorage:
		committee = e.storageCommittee
	case scheduler.KindComputeTxnScheduler:
		committee = e.txnSchedulerCommittee
	default:
		return fmt.Errorf("epoch: unsupported committee kind: %s", kind)
	}

	for _, sig := range sigs {
		if !committee.PublicKeys[sig.PublicKey] {
			return fmt.Errorf("epoch: signature is not from a valid committee member")
		}
	}
	return nil
}

// Group encapsulates communication with a group of nodes in the compute committees.
type Group struct {
	sync.RWMutex

	identity  *identity.Identity
	runtimeID common.Namespace

	consensus consensus.Backend

	handler MessageHandler

	activeEpoch *epoch
	// p2p may be nil.
	p2p *p2p.P2P
	// nodes is a node descriptor watcher for all nodes that are part of any of our committees.
	nodes committee.NodeDescriptorWatcher

	logger *logging.Logger
}

// RoundTransition processes a round transition that just happened.
func (g *Group) RoundTransition() {
	g.Lock()
	defer g.Unlock()

	if g.activeEpoch == nil {
		return
	}

	(g.activeEpoch.cancelRoundCtx)()

	ctx, cancel := context.WithCancel(g.activeEpoch.epochCtx)
	g.activeEpoch.roundCtx = ctx
	g.activeEpoch.cancelRoundCtx = cancel
}

// Suspend processes a runtime suspension that just happened.
//
// Resumption will be processed as a regular epoch transition.
func (g *Group) Suspend(ctx context.Context) {
	g.Lock()
	defer g.Unlock()

	if g.activeEpoch == nil {
		return
	}

	// Cancel context for the previous epoch.
	(g.activeEpoch.cancelEpochCtx)()
	// Invalidate current epoch.
	g.activeEpoch = nil
}

// EpochTransition processes an epoch transition that just happened.
func (g *Group) EpochTransition(ctx context.Context, height int64) error {
	g.Lock()
	defer g.Unlock()

	// Cancel context for the previous epoch.
	if g.activeEpoch != nil {
		(g.activeEpoch.cancelEpochCtx)()
	}

	// Invalidate current epoch. In case we cannot process this transition,
	// this should cause the node to transition into NotReady and stay there
	// until the next epoch transition.
	g.activeEpoch = nil
	// Reset watched nodes.
	g.nodes.Reset()
	defer func() {
		// Make sure there are no unneeded watched nodes in case this method fails.
		if g.activeEpoch == nil {
			g.nodes.Reset()
		}
	}()

	// Request committees from scheduler.
	committees, err := g.consensus.Scheduler().GetCommittees(ctx, &scheduler.GetCommitteesRequest{
		RuntimeID: g.runtimeID,
		Height:    height,
	})
	if err != nil {
		return fmt.Errorf("group: failed to get committees: %w", err)
	}

	// Find the current committees.
	executorCommittees := make(map[hash.Hash]*CommitteeInfo)
	executorCommitteeMemberSet := make(map[signature.PublicKey]bool)
	var executorCommittee, txnSchedulerCommittee, mergeCommittee, storageCommittee *CommitteeInfo
	var executorCommitteeID hash.Hash
	var txnSchedulerLeader signature.PublicKey
	publicIdentity := g.identity.NodeSigner.Public()
	for _, cm := range committees {
		var role scheduler.Role
		var leader signature.PublicKey
		publicKeys := make(map[signature.PublicKey]bool)
		for _, member := range cm.Members {
			publicKeys[member.PublicKey] = true
			if member.PublicKey.Equal(publicIdentity) {
				role = member.Role
			}

			// Start watching the member's node descriptor.
			if _, err = g.nodes.WatchNode(ctx, member.PublicKey); err != nil {
				return fmt.Errorf("group: failed to fetch node info: %w", err)
			}

			if member.Role == scheduler.Leader {
				leader = member.PublicKey
			}
		}

		ci := &CommitteeInfo{
			Role:       role,
			Committee:  cm,
			PublicKeys: publicKeys,
		}

		switch cm.Kind {
		case scheduler.KindComputeExecutor:
			// There can be multiple executor committees per runtime.
			cID := cm.EncodedMembersHash()
			executorCommittees[cID] = ci
			if role != scheduler.Invalid {
				if executorCommittee != nil {
					return fmt.Errorf("member of multiple executor committees")
				}

				executorCommittee = ci
				executorCommitteeID = cID
			}

			for _, m := range cm.Members {
				executorCommitteeMemberSet[m.PublicKey] = true
			}
		case scheduler.KindComputeTxnScheduler:
			txnSchedulerCommittee = ci
			if leader.IsValid() {
				txnSchedulerLeader = leader
			}
		case scheduler.KindComputeMerge:
			mergeCommittee = ci
		case scheduler.KindStorage:
			storageCommittee = ci
		}
	}
	if len(executorCommittees) == 0 {
		return fmt.Errorf("no executor committees")
	}
	if txnSchedulerCommittee == nil {
		return fmt.Errorf("no transaction scheduler committee")
	}
	if mergeCommittee == nil {
		return fmt.Errorf("no merge committee")
	}
	if storageCommittee == nil {
		return fmt.Errorf("no storage committee")
	}

	// Fetch the new epoch.
	epochNumber, err := g.consensus.EpochTime().GetEpoch(ctx, height)
	if err != nil {
		return err
	}

	// Fetch current runtime descriptor.
	runtime, err := g.consensus.Registry().GetRuntime(ctx, &registry.NamespaceQuery{ID: g.runtimeID, Height: height})
	if err != nil {
		return err
	}

	// Create a new epoch and round contexts.
	epochCtx, cancelEpochCtx := context.WithCancel(ctx)
	roundCtx, cancelRoundCtx := context.WithCancel(epochCtx)

	// Update the current epoch.
	g.activeEpoch = &epoch{
		epochNumber:                epochNumber,
		epochCtx:                   epochCtx,
		cancelEpochCtx:             cancelEpochCtx,
		roundCtx:                   roundCtx,
		cancelRoundCtx:             cancelRoundCtx,
		groupVersion:               height,
		executorCommittee:          executorCommittee,
		executorCommitteeID:        executorCommitteeID,
		executorCommittees:         executorCommittees,
		executorCommitteeMemberSet: executorCommitteeMemberSet,
		txnSchedulerCommittee:      txnSchedulerCommittee,
		txnSchedulerLeader:         txnSchedulerLeader,
		mergeCommittee:             mergeCommittee,
		storageCommittee:           storageCommittee,
		runtime:                    runtime,
	}

	// Executor committee may be nil in case we are not a member of any committee.
	var executorRole scheduler.Role
	if executorCommittee != nil {
		executorRole = executorCommittee.Role
	}

	g.logger.Info("epoch transition complete",
		"group_version", height,
		"executor_role", executorRole,
		"txn_scheduler_role", txnSchedulerCommittee.Role,
		"merge_role", mergeCommittee.Role,
	)

	return nil
}

// Nodes returns a node descriptor lookup interface that watches all nodes in our committees.
func (g *Group) Nodes() committee.NodeDescriptorLookup {
	return g.nodes
}

// GetEpochSnapshot returns a snapshot of the currently active epoch.
func (g *Group) GetEpochSnapshot() *EpochSnapshot {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return &EpochSnapshot{}
	}

	s := &EpochSnapshot{
		epochNumber:  g.activeEpoch.epochNumber,
		groupVersion: g.activeEpoch.groupVersion,
		// NOTE: Transaction scheduler and merge committees are always set.
		txnSchedulerRole:      g.activeEpoch.txnSchedulerCommittee.Role,
		mergeRole:             g.activeEpoch.mergeCommittee.Role,
		runtime:               g.activeEpoch.runtime,
		executorCommittees:    g.activeEpoch.executorCommittees,
		txnSchedulerCommittee: g.activeEpoch.txnSchedulerCommittee,
		mergeCommittee:        g.activeEpoch.mergeCommittee,
		storageCommittee:      g.activeEpoch.storageCommittee,
		nodes:                 g.nodes,
	}

	// Executor committee may be nil in case we are not a member of any committee.
	xc := g.activeEpoch.executorCommittee
	if xc != nil {
		s.executorRole = xc.Role
		s.executorCommitteeID = g.activeEpoch.executorCommitteeID
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

	// If we are in the executor committee, we accept messages from the transaction
	// scheduler committee leader.
	if g.activeEpoch.executorCommittee != nil && g.activeEpoch.txnSchedulerLeader.IsValid() {
		n := g.nodes.LookupByPeerID(peerID)
		if n != nil {
			authorized = authorized || g.activeEpoch.txnSchedulerLeader.Equal(n.ID)
		}
	}

	// If we are in the merge committee, we accept messages from any executor committee member.
	if g.activeEpoch.mergeCommittee.Role != scheduler.Invalid {
		n := g.nodes.LookupByPeerID(peerID)
		if n != nil {
			authorized = authorized || g.activeEpoch.executorCommitteeMemberSet[n.ID]
		}
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
			return nil, fmt.Errorf("group version mismatch")
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
	if g.p2p == nil {
		return fmt.Errorf("group: p2p transport is not enabled")
	}

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
	for id := range ci.PublicKeys {
		if id.Equal(publicIdentity) {
			// Do not publish to self.
			continue
		}

		n := g.nodes.Lookup(id)
		if n == nil {
			// This should never happen as nodes cannot disappear mid-epoch.
			g.logger.Warn("ignoring node that disappeared mid-epoch",
				"node", id,
			)
			continue
		}

		g.logger.Debug("publishing to committee member",
			"node", n,
		)

		g.p2p.Publish(pubCtx, n, msg)
	}

	return nil
}

// PublishScheduledBatch publishes a batch to all members in the executor committee.
// Returns the transaction scheduler's signature for this batch.
func (g *Group) PublishScheduledBatch(
	spanCtx opentracing.SpanContext,
	committeeID hash.Hash,
	ioRoot hash.Hash,
	storageSignatures []signature.Signature,
	hdr block.Header,
) (*signature.Signature, error) {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.txnSchedulerCommittee.Role != scheduler.Leader {
		return nil, fmt.Errorf("group: not leader of txn scheduler committee")
	}

	xc := g.activeEpoch.executorCommittees[committeeID]
	if xc == nil {
		return nil, fmt.Errorf("group: invalid executor committee")
	}

	dispatchMsg := &commitment.TxnSchedulerBatchDispatch{
		CommitteeID:       committeeID,
		IORoot:            ioRoot,
		StorageSignatures: storageSignatures,
		Header:            hdr,
	}

	signedDispatchMsg, err := commitment.SignTxnSchedulerBatchDispatch(g.identity.NodeSigner, dispatchMsg)
	if err != nil {
		return nil, fmt.Errorf("group: unable to sign txn scheduler batch dispatch msg: %w", err)
	}

	return &signedDispatchMsg.Signature, g.publishLocked(
		spanCtx,
		xc,
		&p2p.Message{
			SignedTxnSchedulerBatchDispatch: signedDispatchMsg,
		},
	)
}

// PublishExecuteFinished publishes an execute commitment to all members in the merge
// committee.
func (g *Group) PublishExecuteFinished(spanCtx opentracing.SpanContext, c *commitment.ExecutorCommitment) error {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil || g.activeEpoch.executorCommittee == nil {
		return fmt.Errorf("group: not member of executor committee")
	}

	return g.publishLocked(
		spanCtx,
		g.activeEpoch.mergeCommittee,
		&p2p.Message{
			ExecutorWorkerFinished: &p2p.ExecutorWorkerFinished{
				Commitment: *c,
			},
		},
	)
}

// NewGroup creates a new group.
func NewGroup(
	ctx context.Context,
	identity *identity.Identity,
	runtimeID common.Namespace,
	handler MessageHandler,
	consensus consensus.Backend,
	p2p *p2p.P2P,
) (*Group, error) {
	nodes, err := committee.NewNodeDescriptorWatcher(ctx, consensus.Registry())
	if err != nil {
		return nil, fmt.Errorf("group: failed to create node watcher: %w", err)
	}

	g := &Group{
		identity:  identity,
		runtimeID: runtimeID,
		consensus: consensus,
		handler:   handler,
		p2p:       p2p,
		nodes:     nodes,
		logger:    logging.GetLogger("worker/common/committee/group").With("runtime_id", runtimeID),
	}

	if p2p != nil {
		p2p.RegisterHandler(runtimeID, g)
	}

	return g, nil
}
