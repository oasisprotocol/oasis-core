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
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
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
	Nodes      []*node.Node
	PublicKeys map[signature.PublicKey]bool
}

type epoch struct {
	roundCtx       context.Context
	cancelRoundCtx context.CancelFunc

	// groupVersion is the consensus backend block height of the last processed
	// committee election.
	groupVersion int64

	// executorCommittee is the executor committee we are a member of.
	executorCommittee *CommitteeInfo
	// executorCommitteeID is the identifier of our executor committee.
	executorCommitteeID hash.Hash
	// executorCommittees are all executor committees.
	executorCommittees map[hash.Hash]*CommitteeInfo
	// executorCommitteesByPeer is a set of P2P public keys of executor committee
	// members.
	executorCommitteesByPeer map[signature.PublicKey]bool

	// txnSchedulerCommitee is the txn scheduler committee we are a member of.
	txnSchedulerCommittee *CommitteeInfo
	// txnSchedulerLeaderPeerID is the P2P public key of txn scheduler leader.
	txnSchedulerLeaderPeerID signature.PublicKey

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

	executorRole     scheduler.Role
	txnSchedulerRole scheduler.Role
	mergeRole        scheduler.Role

	runtime *registry.Runtime

	executorCommittees    map[hash.Hash]*CommitteeInfo
	txnSchedulerCommittee *CommitteeInfo
	mergeCommittee        *CommitteeInfo
	storageCommittee      *CommitteeInfo
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

// Group encapsulates communication with a group of nodes in the
// executor committee.
type Group struct {
	sync.RWMutex

	identity  *identity.Identity
	runtimeID common.Namespace

	scheduler scheduler.Backend
	registry  registry.Backend
	roothash  roothash.Backend

	handler MessageHandler

	activeEpoch *epoch
	// p2p may be nil.
	p2p *p2p.P2P

	logger *logging.Logger
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
	(g.activeEpoch.cancelRoundCtx)()
	// Invalidate current epoch.
	g.activeEpoch = nil
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
	committees, err = g.scheduler.GetCommittees(ctx, &scheduler.GetCommitteesRequest{
		RuntimeID: g.runtimeID,
		Height:    height,
	})
	if err != nil {
		return err
	}

	publicIdentity := g.identity.NodeSigner.Public()

	// Find the current committees.
	executorCommittees := make(map[hash.Hash]*CommitteeInfo)
	executorCommitteesByPeer := make(map[signature.PublicKey]bool)
	var executorCommittee, txnSchedulerCommittee, mergeCommittee, storageCommittee *CommitteeInfo
	var executorCommitteeID hash.Hash
	var txnSchedulerLeaderPeerID signature.PublicKey
	for _, cm := range committees {
		var nodes []*node.Node
		var role scheduler.Role
		publicKeys := make(map[signature.PublicKey]bool)
		leader := -1
		for idx, member := range cm.Members {
			publicKeys[member.PublicKey] = true
			if member.PublicKey.Equal(publicIdentity) {
				role = member.Role
			}

			// Fetch peer node information from the registry.
			var n *node.Node
			n, err = g.registry.GetNode(ctx, &registry.IDQuery{ID: member.PublicKey, Height: height})
			if err != nil {
				return fmt.Errorf("group: failed to fetch node info: %w", err)
			}

			nodes = append(nodes, n)

			if member.Role == scheduler.Leader {
				leader = idx
			}
		}

		ci := &CommitteeInfo{
			Role:       role,
			Committee:  cm,
			Nodes:      nodes,
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

			for _, n := range nodes {
				executorCommitteesByPeer[n.P2P.ID] = true
			}
		case scheduler.KindComputeTxnScheduler:
			txnSchedulerCommittee = ci
			if leader != -1 {
				txnSchedulerLeaderPeerID = nodes[leader].P2P.ID
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

	// Fetch current runtime descriptor.
	runtime, err := g.registry.GetRuntime(ctx, &registry.NamespaceQuery{ID: g.runtimeID, Height: height})
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
		executorCommittee,
		executorCommitteeID,
		executorCommittees,
		executorCommitteesByPeer,
		txnSchedulerCommittee,
		txnSchedulerLeaderPeerID,
		mergeCommittee,
		storageCommittee,
		runtime,
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

// GetEpochSnapshot returns a snapshot of the currently active epoch.
func (g *Group) GetEpochSnapshot() *EpochSnapshot {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return &EpochSnapshot{}
	}

	s := &EpochSnapshot{
		groupVersion: g.activeEpoch.groupVersion,
		// NOTE: Transaction scheduler and merge committees are always set.
		txnSchedulerRole:      g.activeEpoch.txnSchedulerCommittee.Role,
		mergeRole:             g.activeEpoch.mergeCommittee.Role,
		runtime:               g.activeEpoch.runtime,
		executorCommittees:    g.activeEpoch.executorCommittees,
		txnSchedulerCommittee: g.activeEpoch.txnSchedulerCommittee,
		mergeCommittee:        g.activeEpoch.mergeCommittee,
		storageCommittee:      g.activeEpoch.storageCommittee,
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
	if g.activeEpoch.executorCommittee != nil && g.activeEpoch.txnSchedulerLeaderPeerID.IsValid() {
		authorized = authorized || peerID.Equal(g.activeEpoch.txnSchedulerLeaderPeerID)
	}

	// If we are in the merge committee, we accept messages from any executor committee member.
	if g.activeEpoch.mergeCommittee.Role != scheduler.Invalid {
		authorized = authorized || g.activeEpoch.executorCommitteesByPeer[peerID]
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
	for index, member := range ci.Committee.Members {
		g.logger.Debug("publishing to committee members",
			"node", ci.Nodes[index],
		)
		if member.PublicKey.Equal(publicIdentity) {
			// Do not publish to self.
			continue
		}

		g.p2p.Publish(pubCtx, ci.Nodes[index], msg)
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
	identity *identity.Identity,
	runtimeID common.Namespace,
	handler MessageHandler,
	registry registry.Backend,
	roothash roothash.Backend,
	scheduler scheduler.Backend,
	p2p *p2p.P2P,
) (*Group, error) {
	g := &Group{
		identity:  identity,
		runtimeID: runtimeID,
		scheduler: scheduler,
		registry:  registry,
		roothash:  roothash,
		handler:   handler,
		p2p:       p2p,
		logger:    logging.GetLogger("worker/common/committee/group").With("runtime_id", runtimeID),
	}

	if p2p != nil {
		p2p.RegisterHandler(runtimeID, g)
	}

	return g, nil
}
