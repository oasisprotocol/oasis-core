package committee

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	opentracingExt "github.com/opentracing/opentracing-go/ext"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/tracing"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	storageClient "github.com/oasisprotocol/oasis-core/go/storage/client"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
)

const (
	// peerMessageProcessTimeout is the maximum time that peer message processing can take.
	peerMessageProcessTimeout = 10 * time.Second

	// tagStorage is the committee node descriptor tag to use for storage nodes.
	tagStorage = "storage"
	// tagExecutor is the committee node descriptor tag to use for executor nodes.
	tagExecutor = "executor"
)

// TagForCommittee returns node lookup tag for scheduler committee kind.
func TagForCommittee(kind scheduler.CommitteeKind) string {
	switch kind {
	case scheduler.KindComputeExecutor:
		return tagExecutor
	case scheduler.KindStorage:
		return tagStorage
	default:
		return ""
	}
}

// MessageHandler handles messages from other nodes.
type MessageHandler interface {
	// HandlePeerMessage handles a message that has already been authenticated to come from a
	// registered node.
	//
	// The provided context is short-lived so if the handler needs to perform additional work, that
	// should be dispatched to a separate goroutine and not block delivery.
	HandlePeerMessage(ctx context.Context, msg *p2p.Message, isOwn bool) error
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
	epochNumber beacon.EpochTime

	// executorCommittee is the executor committee we are a member of.
	executorCommittee *CommitteeInfo

	// storageCommittee is the storage committee we are a member of.
	storageCommittee *CommitteeInfo

	runtime *registry.Runtime
}

// EpochSnapshot is an immutable snapshot of epoch state.
type EpochSnapshot struct {
	identity     *identity.Identity
	groupVersion int64

	epochNumber beacon.EpochTime

	runtime *registry.Runtime

	executorCommittee *CommitteeInfo
	storageCommittee  *CommitteeInfo

	nodes nodes.VersionedNodeDescriptorWatcher
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

// GetExecutorCommittee returns the current executor committee.
func (e *EpochSnapshot) GetExecutorCommittee() *CommitteeInfo {
	return e.executorCommittee
}

// GetEpochNumber returns the sequential number of the epoch.
func (e *EpochSnapshot) GetEpochNumber() beacon.EpochTime {
	return e.epochNumber
}

// IsExecutorMember checks if the current node is a member of the executor committee
// in the current epoch.
func (e *EpochSnapshot) IsExecutorMember() bool {
	if e.executorCommittee == nil {
		return false
	}
	return e.executorCommittee.Role != scheduler.RoleInvalid
}

// IsExecutorWorker checks if the current node is a worker of the executor committee
// in the current epoch.
func (e *EpochSnapshot) IsExecutorWorker() bool {
	if e.executorCommittee == nil {
		return false
	}
	return e.executorCommittee.Role == scheduler.RoleWorker
}

// IsExecutorBackupWorker checks if the current node is a backup worker of the executor
// committee in the current epoch.
func (e *EpochSnapshot) IsExecutorBackupWorker() bool {
	if e.executorCommittee == nil {
		return false
	}
	return e.executorCommittee.Role == scheduler.RoleBackupWorker
}

// IsTransactionScheduler checks if the current node is a a transaction scheduler
// at the specific runtime round.
func (e *EpochSnapshot) IsTransactionScheduler(round uint64) bool {
	if e.executorCommittee == nil || e.executorCommittee.Committee == nil {
		return false
	}
	scheduler, err := commitment.GetTransactionScheduler(e.executorCommittee.Committee, round)
	if err != nil {
		return false
	}
	return scheduler.PublicKey.Equal(e.identity.NodeSigner.Public())
}

// GetStorageCommittee returns the current storage committee.
func (e *EpochSnapshot) GetStorageCommittee() *CommitteeInfo {
	return e.storageCommittee
}

// Nodes returns a node descriptor lookup interface.
func (e *EpochSnapshot) Nodes() nodes.NodeDescriptorLookup {
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

// VerifyTxnSchedulerSignature verifies transaction scheduler signature.
//
// Implements commitment.SignatureVerifier.
func (e *EpochSnapshot) VerifyTxnSchedulerSignature(sig signature.Signature, round uint64) error {
	if e.executorCommittee == nil || e.executorCommittee.Committee == nil {
		return fmt.Errorf("epoch: no active transaction scheduler")
	}
	scheduler, err := commitment.GetTransactionScheduler(e.executorCommittee.Committee, round)
	if err != nil {
		return fmt.Errorf("epoch: error getting transaction scheduler: %w", err)
	}
	if !scheduler.PublicKey.Equal(sig.PublicKey) {
		return fmt.Errorf("epoch: signature is not from the transaction scheduler at round: %d", round)
	}
	return nil
}

// Group encapsulates communication with a group of nodes in the runtime committees.
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
	nodes nodes.VersionedNodeDescriptorWatcher
	// storage is the storage backend that tracks the current committee.
	storage storage.ClientBackend

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
	var executorCommittee, storageCommittee *CommitteeInfo
	publicIdentity := g.identity.NodeSigner.Public()
	for _, cm := range committees {
		var role scheduler.Role
		publicKeys := make(map[signature.PublicKey]bool)
		for _, member := range cm.Members {
			publicKeys[member.PublicKey] = true
			if member.PublicKey.Equal(publicIdentity) {
				role = member.Role
			}

			// Start watching the member's node descriptor.
			if _, err = g.nodes.WatchNodeWithTag(ctx, member.PublicKey, TagForCommittee(cm.Kind)); err != nil {
				return fmt.Errorf("group: failed to fetch node info: %w", err)
			}
		}

		ci := &CommitteeInfo{
			Role:       role,
			Committee:  cm,
			PublicKeys: publicKeys,
		}

		switch cm.Kind {
		case scheduler.KindComputeExecutor:
			executorCommittee = ci
		case scheduler.KindStorage:
			storageCommittee = ci
		}
	}
	if executorCommittee == nil {
		return fmt.Errorf("group: no executor committee")
	}
	if storageCommittee == nil {
		return fmt.Errorf("group: no storage committee")
	}

	// Fetch the new epoch.
	epochNumber, err := g.consensus.Beacon().GetEpoch(ctx, height)
	if err != nil {
		return err
	}

	// Fetch the epoch block, which is also the group version.
	// Note: when node is restarted, `EpochTransition` is called on the first
	// received block, which is not necessary the actual epoch transition block.
	// Therefore we cannot use current height as the group version.
	groupVersion, err := g.consensus.Beacon().GetEpochBlock(ctx, epochNumber)
	if err != nil {
		return err
	}

	// Fetch current runtime descriptor.
	runtime, err := g.consensus.Registry().GetRuntime(ctx, &registry.NamespaceQuery{ID: g.runtimeID, Height: height})
	if err != nil {
		return err
	}

	// Freeze the committee and make sure the storage client has been updated.
	g.nodes.Freeze(height)
	if err = g.storage.EnsureCommitteeVersion(ctx, height); err != nil {
		return fmt.Errorf("group: failed to ensure committee version: %w", err)
	}

	// Create a new epoch and round contexts.
	epochCtx, cancelEpochCtx := context.WithCancel(ctx)
	roundCtx, cancelRoundCtx := context.WithCancel(epochCtx)

	// Update the current epoch.
	g.activeEpoch = &epoch{
		epochNumber:       epochNumber,
		epochCtx:          epochCtx,
		cancelEpochCtx:    cancelEpochCtx,
		roundCtx:          roundCtx,
		cancelRoundCtx:    cancelRoundCtx,
		groupVersion:      groupVersion,
		executorCommittee: executorCommittee,
		storageCommittee:  storageCommittee,
		runtime:           runtime,
	}

	g.logger.Info("epoch transition complete",
		"group_version", groupVersion,
		"executor_role", executorCommittee.Role,
	)

	return nil
}

// Nodes returns a node descriptor lookup interface that watches all nodes in our committees.
func (g *Group) Nodes() nodes.NodeDescriptorLookup {
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
		identity:          g.identity,
		epochNumber:       g.activeEpoch.epochNumber,
		groupVersion:      g.activeEpoch.groupVersion,
		runtime:           g.activeEpoch.runtime,
		executorCommittee: g.activeEpoch.executorCommittee,
		storageCommittee:  g.activeEpoch.storageCommittee,
		nodes:             g.nodes,
	}

	return s
}

// AuthenticatePeer handles authenticating a peer that send an incoming message.
func (g *Group) AuthenticatePeer(peerID signature.PublicKey, msg *p2p.Message) error {
	g.RLock()
	defer g.RUnlock()

	if g.activeEpoch == nil {
		return fmt.Errorf("group: no active epoch")
	}

	if msg.GroupVersion < g.activeEpoch.groupVersion {
		return p2pError.Permanent(fmt.Errorf("group version in the past"))
	}

	// If we are in the executor committee, we accept messages from all nodes.
	// Otherwise reject and relay the message.
	authorized := g.activeEpoch.executorCommittee.Role != scheduler.RoleInvalid
	if !authorized {
		err := fmt.Errorf("group: peer is not authorized")

		// In case the message is for current epoch and not authorized,
		// make the error permanent to avoid retrying. The message should
		// still be relayed.
		if msg.GroupVersion == g.activeEpoch.groupVersion {
			err = p2pError.Permanent(p2pError.Relayable(err))
		}

		return err
	}

	return nil
}

// HandlePeerMessage handles an incoming message from a peer.
func (g *Group) HandlePeerMessage(unusedPeerID signature.PublicKey, msg *p2p.Message, isOwn bool) error {
	// Perform some checks on the incoming message. We make sure to release the
	// lock before running the handler.
	err := func() error {
		g.RLock()
		defer g.RUnlock()

		if g.activeEpoch == nil {
			return fmt.Errorf("group: no active epoch")
		}

		// Ensure that both peers have the same view of the current group. If this
		// is not the case, this means that one of the nodes processed an epoch
		// transition and the other one didn't.
		switch {
		case msg.GroupVersion < g.activeEpoch.groupVersion:
			// Stale messages will never become valid.
			return p2pError.Permanent(fmt.Errorf("group version in the past"))
		case msg.GroupVersion > g.activeEpoch.groupVersion:
			// Messages from the future may eventually become valid.
			return fmt.Errorf("group version from the future")
		}

		return nil
	}()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), peerMessageProcessTimeout)
	defer cancel()

	// Import SpanContext from the message and store it in the current Context.
	if msg.SpanContext != nil {
		sc, err := tracing.SpanContextFromBinary(msg.SpanContext)
		if err == nil {
			parentSpan := opentracing.StartSpan("parent", opentracingExt.RPCServerOption(sc))
			span := opentracing.StartSpan("HandleBatch", opentracing.FollowsFrom(parentSpan.Context()))
			defer span.Finish()
			ctx = opentracing.ContextWithSpan(ctx, span)
		}
	}

	return g.handler.HandlePeerMessage(ctx, msg, isOwn)
}

// Publish publishes a message to the P2P network.
func (g *Group) Publish(spanCtx opentracing.SpanContext, msg *p2p.Message) error {
	g.RLock()
	defer g.RUnlock()

	if g.p2p == nil {
		return fmt.Errorf("group: p2p transport is not enabled")
	}
	if g.activeEpoch == nil {
		return fmt.Errorf("group: no active epoch")
	}

	pubCtx := g.activeEpoch.roundCtx

	var scBinary []byte
	if spanCtx != nil {
		scBinary, _ = tracing.SpanContextToBinary(spanCtx)
	}

	// Populate message fields.
	msg.GroupVersion = g.activeEpoch.groupVersion
	msg.SpanContext = scBinary

	// Publish message to the P2P network.
	g.p2p.Publish(pubCtx, g.runtimeID, msg)

	return nil
}

// Peers returns a list of connected P2P peers.
func (g *Group) Peers() []string {
	if g.p2p == nil {
		return nil
	}
	return g.p2p.Peers(g.runtimeID)
}

// Storage returns the storage client backend that talks to the runtime group.
func (g *Group) Storage() storage.Backend {
	return g.storage
}

// NewGroup creates a new group.
func NewGroup(
	ctx context.Context,
	identity *identity.Identity,
	runtime runtimeRegistry.Runtime,
	handler MessageHandler,
	consensus consensus.Backend,
	p2p *p2p.P2P,
) (*Group, error) {
	nw, err := nodes.NewVersionedNodeDescriptorWatcher(ctx, consensus.Registry())
	if err != nil {
		return nil, fmt.Errorf("group: failed to create node watcher: %w", err)
	}

	// TODO: If the current node is a storage node, always include self (oasis-core#3251).
	sc, err := storageClient.NewForNodes(
		ctx,
		identity,
		nodes.NewFilteredNodeLookup(nw, nodes.TagFilter(TagForCommittee(scheduler.KindStorage))),
		runtime,
	)
	if err != nil {
		return nil, fmt.Errorf("group: failed to create storage client: %w", err)
	}

	g := &Group{
		identity:  identity,
		runtimeID: runtime.ID(),
		consensus: consensus,
		handler:   handler,
		p2p:       p2p,
		nodes:     nw,
		storage:   sc.(storage.ClientBackend),
		logger:    logging.GetLogger("worker/common/committee/group").With("runtime_id", runtime.ID()),
	}

	if p2p != nil {
		p2p.RegisterHandler(runtime.ID(), g)
	}

	return g, nil
}
