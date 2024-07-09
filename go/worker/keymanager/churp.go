package keymanager

import (
	"container/heap"
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p/core"
	"golang.org/x/exp/maps"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	workerKm "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
)

const (
	// maxAttempts is the maximum number of attempts to submit an application
	// for a handoff, or to fetch switch points or bivariate shares during
	// a handoff.
	maxAttempts = 10

	// dimensionSwitchDelay is the block delay between dimension switches.
	dimensionSwitchDelay = 2

	// retryInitialInterval is the initial time interval for the exponential
	// back-off used between retries.
	retryInitialInterval = time.Second
)

var (
	// insecureChurpRPCMethods contains allowed insecure RPC methods.
	insecureChurpRPCMethods = map[string]struct{}{
		churp.RPCMethodVerificationMatrix: {},
	}

	// secureChurpRPCMethods contains allowed secure RPC methods.
	secureChurpRPCMethods = map[string]struct{}{
		churp.RPCMethodShareReductionPoint:    {},
		churp.RPCMethodShareDistributionPoint: {},
		churp.RPCMethodBivariateShare:         {},
		churp.RPCMethodSGXPolicyKeyShare:      {},
	}
)

// Ensure the CHURP worker implements the RPCAccessController interface.
var _ workerKm.RPCAccessController = (*churpWorker)(nil)

// churpWorker executes the CHURP protocol for the configured schemes.
type churpWorker struct {
	logger *logging.Logger

	initCh chan struct{}

	kmWorker *Worker

	mu     sync.RWMutex
	churps map[uint8]*churp.Status // Guarded by mutex.

	watcher     *nodeWatcher
	submissions *submissionScheduler
	handoffs    *handoffExecutor
	finisher    *handoffFinisher
}

// newChurpWorker constructs a new key manager CHURP worker.
func newChurpWorker(kmWorker *Worker) (*churpWorker, error) {
	// Read the configuration to determine in which schemes the worker
	// should participate.
	churps := make(map[uint8]*churp.Status)
	for _, cfg := range config.GlobalConfig.Keymanager.Churp.Schemes {
		churps[cfg.ID] = nil
	}

	return &churpWorker{
		logger:      logging.GetLogger("worker/keymanager/churp"),
		initCh:      make(chan struct{}),
		kmWorker:    kmWorker,
		churps:      churps,
		watcher:     newNodeWatcher(kmWorker.peerMap),
		submissions: newSubmissionScheduler(kmWorker),
		handoffs:    newHandoffExecutor(kmWorker),
		finisher:    newHandoffFinisher(kmWorker),
	}, nil
}

// Methods implements RPCAccessController interface.
func (w *churpWorker) Methods() []string {
	var methods []string
	methods = append(methods, maps.Keys(secureChurpRPCMethods)...)
	methods = append(methods, maps.Keys(insecureChurpRPCMethods)...)
	return methods
}

// Connect implements RPCAccessController interface.
func (w *churpWorker) Connect(ctx context.Context, peerID core.PeerID) (b bool) {
	// Secure methods are accessible to peers that pass authorization.
	if err := w.authorizeNode(ctx, peerID); err == nil {
		return true
	}
	if err := w.authorizeKeyManager(peerID); err == nil {
		return true
	}

	return false
}

// Authorize implements RPCAccessController interface.
func (w *churpWorker) Authorize(ctx context.Context, method string, kind enclaverpc.Kind, peerID core.PeerID) (err error) {
	// Check if the method is supported.
	switch kind {
	case enclaverpc.KindInsecureQuery:
		if _, ok := insecureChurpRPCMethods[method]; !ok {
			return fmt.Errorf("unsupported method: %s", method)
		}
	case enclaverpc.KindNoiseSession:
		if _, ok := secureChurpRPCMethods[method]; !ok {
			return fmt.Errorf("unsupported method: %s", method)
		}
	default:
		return fmt.Errorf("unsupported kind: %s", kind)
	}

	// All peers must undergo the authorization process.
	switch method {
	case churp.RPCMethodSGXPolicyKeyShare:
		return w.authorizeNode(ctx, peerID)
	case churp.RPCMethodVerificationMatrix,
		churp.RPCMethodShareReductionPoint,
		churp.RPCMethodShareDistributionPoint,
		churp.RPCMethodBivariateShare:
		return w.authorizeKeyManager(peerID)
	default:
		return fmt.Errorf("unsupported method: %s", method)
	}
}

func (w *churpWorker) authorizeNode(ctx context.Context, peerID core.PeerID) error {
	rt, err := w.kmWorker.runtime.RegistryDescriptor(ctx)
	if err != nil {
		return err
	}

	switch rt.TEEHardware {
	case node.TEEHardwareInvalid:
		// Insecure key manager enclaves can be queried by all runtimes (used for testing).
		return nil
	case node.TEEHardwareIntelSGX:
		// Secure key manager enclaves can be queried by runtimes specified in the policy.
		w.mu.RLock()
		statuses := maps.Values(w.churps)
		w.mu.RUnlock()

		// Retrieve the list of runtimes that the peer participates in.
		rts := w.kmWorker.accessList.Runtimes(peerID)

		// Grant access if the peer participates in any allowed runtime.
		for _, status := range statuses {
			if status == nil {
				continue
			}
			for rt := range status.Policy.Policy.MayQuery {
				if rts.Contains(rt) {
					return nil
				}
			}
		}
		return fmt.Errorf("query not allowed")
	default:
		return fmt.Errorf("unsupported hardware: %s", rt.TEEHardware)
	}
}

func (w *churpWorker) authorizeKeyManager(peerID core.PeerID) error {
	// Allow only peers within the same key manager runtime.
	if !w.kmWorker.accessList.Runtimes(peerID).Contains(w.kmWorker.runtimeID) {
		return fmt.Errorf("not a key manager")
	}

	// Allow only peers that want to form a new committee.
	if !w.watcher.HasApplied(peerID) {
		return fmt.Errorf("not applied to form committee")
	}

	return nil
}

// Initialized returns a channel that will be closed when the worker
// is initialized.
func (w *churpWorker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetStatus returns the worker status.
func (w *churpWorker) GetStatus() workerKm.ChurpStatus {
	w.mu.RLock()
	defer w.mu.RUnlock()

	status := workerKm.ChurpStatus{
		Schemes: make(map[uint8]workerKm.ChurpSchemeStatus),
	}

	for id, st := range w.churps {
		status.Schemes[id] = workerKm.ChurpSchemeStatus{
			Status: st,
		}
	}

	return status
}

func (w *churpWorker) work(ctx context.Context, _ host.RichRuntime) {
	w.logger.Info("starting worker",
		"node_id", w.kmWorker.nodeID,
	)

	stCh, stSub := w.kmWorker.backend.Churp().WatchStatuses()
	defer stSub.Close()

	epoCh, epoSub, err := w.kmWorker.commonWorker.Consensus.Beacon().WatchEpochs(ctx)
	if err != nil {
		w.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer epoSub.Close()

	blkCh, blkSub, err := w.kmWorker.commonWorker.Consensus.WatchBlocks(ctx)
	if err != nil {
		w.logger.Error("failed to watch blocks",
			"err", err,
		)
		return
	}
	defer blkSub.Close()

	close(w.initCh)

	for {
		select {
		case epoch := <-epoCh:
			w.handleNewEpoch(epoch)
		case blk := <-blkCh:
			w.handleNewBlock(blk)
		case status := <-stCh:
			w.handleStatusUpdate(status)
		case <-ctx.Done():
			w.logger.Info("stopping worker")
			w.submissions.Stop()
			w.handoffs.Stop()
			w.finisher.Stop()
			return
		}
	}
}

// handleNewEpoch is responsible for handling a new epoch.
func (w *churpWorker) handleNewEpoch(epoch beacon.EpochTime) {
	w.submissions.Cancel(epoch)
	w.submissions.Clear(epoch)

	w.handoffs.Cancel(epoch)
	w.handoffs.Clear(epoch)
}

// handleNewBlock is responsible for handling a new block.
func (w *churpWorker) handleNewBlock(blk *consensus.Block) {
	w.submissions.Start(blk.Height)
	w.handoffs.Start(blk.Height)
}

// handleStatusUpdate is responsible for handling status update.
func (w *churpWorker) handleStatusUpdate(status *churp.Status) {
	// Skip schemes we are not involved in.
	if status.RuntimeID != w.kmWorker.runtimeID {
		return
	}

	w.mu.RLock()
	_, ok := w.churps[status.ID]
	w.mu.RUnlock()

	if !ok {
		return
	}

	w.logger.Debug("status update",
		"status", status,
	)

	// Update status.
	w.mu.Lock()
	w.churps[status.ID] = status
	w.mu.Unlock()

	// Notify all workers about the new status.
	w.watcher.Update(status)
	w.submissions.Queue(status)
	w.handoffs.Queue(status)
	w.finisher.Finalize(status)
}

// submissionScheduler is responsible for generating and submitting
// application requests one epoch before handoffs.
type submissionScheduler struct {
	logger *logging.Logger

	wg sync.WaitGroup

	// kmWorker provides access to the common key manager services.
	kmWorker *Worker

	// submissions contains scheduled application submission tasks.
	submissions TaskQueue
}

// newSubmissionScheduler creates a new submission scheduler.
func newSubmissionScheduler(kmWorker *Worker) *submissionScheduler {
	return &submissionScheduler{
		logger:      logging.GetLogger("worker/keymanager/churp/submission"),
		kmWorker:    kmWorker,
		submissions: newTaskQueue(),
	}
}

// Queue schedules the given CHURP scheme for application submission,
// updating or removing the scheduled submission if already present.
func (s *submissionScheduler) Queue(status *churp.Status) {
	// Stop and remove submission for the previous handoff.
	info, ok := s.submissions.Get(status.ID)
	if ok && info.status.NextHandoff < status.NextHandoff {
		s.submissions.Remove(info, fmt.Errorf("new handoff"))
	}

	// Schedule submission for the current handoff.
	info, ok = s.submissions.Get(status.ID)
	if !ok {
		epoch := status.NextHandoff - 1
		height, err := s.kmWorker.selectBlockHeight(epoch, 20, 50)
		if err != nil {
			s.logger.Error("failed to select a random block height",
				"err", err,
			)
			return
		}

		info = newTaskInfo(status, height)
		s.submissions.Add(info)
	}

	// Stop and remove the submission if the application has already
	// been submitted or if handoffs are disabled.
	switch _, submitted := status.Applications[s.kmWorker.nodeID]; {
	case submitted:
		s.submissions.Remove(info, fmt.Errorf("already submitted"))
	case status.HandoffsDisabled():
		s.submissions.Remove(info, fmt.Errorf("handoffs disabled"))
	}
}

// Start starts all eligible queued submissions.
func (s *submissionScheduler) Start(height int64) {
	for _, info := range s.submissions.Run(beacon.EpochMax, height) {
		ctx, cancel := context.WithCancelCause(context.Background())
		info.cancel = cancel

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.submitApplication(ctx, info.status)
		}()
	}
}

// Stop stops all submissions currently in progress and waits for them
// to complete.
func (s *submissionScheduler) Stop() {
	cause := fmt.Errorf("stopped")
	s.submissions.Stop(cause)
	s.wg.Wait()
}

// Clear removes queued submissions that didn't complete in time,
// while retaining those that are still pending.
func (s *submissionScheduler) Clear(epoch beacon.EpochTime) {
	s.submissions.Clear(epoch + 1)
}

// Cancel sends stop signal to submissions in progress which are not allowed
// to submit applications in the given epoch.
func (s *submissionScheduler) Cancel(epoch beacon.EpochTime) {
	cause := fmt.Errorf("submissions closed: epoch %d", epoch)
	s.submissions.Cancel(epoch+1, cause)
}

// submitApplication tries to submit an application, retrying if generation
// or transaction fails.
func (s *submissionScheduler) submitApplication(ctx context.Context, status *churp.Status) {
	if err := retry(ctx, func(attempt int) error {
		s.logger.Info("trying to submit application",
			"id", status.ID,
			"epoch", status.NextHandoff,
			"attempt", attempt,
		)

		err := s.trySubmitApplication(ctx, status)
		if err != nil {
			s.logger.Debug("failed to submit application",
				"id", status.ID,
				"epoch", status.NextHandoff,
				"attempt", attempt,
				"err", err,
			)
			return err
		}

		return nil
	}); err != nil {
		s.logger.Warn("failed to submit application",
			"id", status.ID,
			"epoch", status.NextHandoff,
			"err", err,
		)
	}
}

// trySubmitApplication tries to submit an application.
func (s *submissionScheduler) trySubmitApplication(ctx context.Context, status *churp.Status) error {
	// Ask enclave to prepare a dealer and return signed verification matrix.
	req := churp.HandoffRequest{
		Identity: churp.Identity{
			ID:        status.ID,
			RuntimeID: s.kmWorker.runtimeID,
		},
		Epoch: status.NextHandoff,
	}
	var rsp churp.SignedApplicationRequest
	if err := s.kmWorker.callEnclaveLocal(ctx, churp.RPCMethodInit, req, &rsp); err != nil {
		return fmt.Errorf("failed to generate verification matrix: %w", err)
	}

	// Validate the signature.
	rak, err := s.kmWorker.runtimeAttestationKey()
	if err != nil {
		return err
	}
	if err = rsp.VerifyRAK(rak); err != nil {
		return fmt.Errorf("failed to verify generate verification matrix response: %w", err)
	}

	// Publish transaction.
	tx := churp.NewApplyTx(0, nil, &rsp)
	if err = consensus.SignAndSubmitTx(ctx, s.kmWorker.commonWorker.Consensus, s.kmWorker.commonWorker.Identity.NodeSigner, tx); err != nil {
		return err
	}

	return nil
}

// handoffExecutor manages the orchestration of handoffs.
type handoffExecutor struct {
	logger *logging.Logger

	wg sync.WaitGroup

	// kmWorker provides access to the common key manager services.
	kmWorker *Worker

	// handoffs contains scheduled handoffs tasks.
	handoffs TaskQueue

	// dimSwitchChs are channels that notify handoffs when the dimension
	// switch timeout has expired, allowing handoffs to proceed to the
	// next switch.
	dimSwitchChs map[int64]chan struct{}
}

// newHandoffExecutor creates a new handoff executor.
func newHandoffExecutor(kmWorker *Worker) *handoffExecutor {
	return &handoffExecutor{
		logger:       logging.GetLogger("worker/keymanager/churp/handoff"),
		kmWorker:     kmWorker,
		handoffs:     newTaskQueue(),
		dimSwitchChs: make(map[int64]chan struct{}),
	}
}

// Queue schedules the given scheme for the next handoff.
//
// If the scheme is already queued, the status is updated.
func (e *handoffExecutor) Queue(status *churp.Status) {
	info, ok := e.handoffs.Get(status.ID)

	// Stop and remove if handoffs are disabled.
	if status.HandoffsDisabled() {
		e.handoffs.Remove(info, fmt.Errorf("handoffs disabled"))
		return
	}

	// Update if the handoff epoch hasn't changed, as new applications
	// may have arrived.
	if ok && info.status.NextHandoff == status.NextHandoff {
		info.status = status
		return
	}

	// Stop and remove if the next handoff completed/failed.
	e.handoffs.Remove(info, fmt.Errorf("handoff ended"))

	// Ignore if we haven't yet applied for the next committee
	// or if confirmation has already been submitted.
	app, ok := status.Applications[e.kmWorker.nodeID]
	if !ok || app.Reconstructed {
		return
	}

	// Select block height deterministically, so that all nodes start
	// at the same time.
	height, err := e.kmWorker.selectBlockHeight(status.NextHandoff, 10, 10)
	if err != nil {
		e.logger.Error("failed to select a random block height",
			"err", err,
		)
		return
	}

	// Schedule.
	info = newTaskInfo(status, height)
	e.handoffs.Add(info)

	e.logger.Info("handoff scheduled",
		"id", status.ID,
		"epoch", status.NextHandoff,
		"height", height,
	)
}

// Start starts all eligible queued handoffs.
func (e *handoffExecutor) Start(height int64) {
	dimSwitchCh := make(chan struct{})
	dimSwitchHeight := height + dimensionSwitchDelay
	e.dimSwitchChs[dimSwitchHeight] = dimSwitchCh

	if waitCh, ok := e.dimSwitchChs[height]; ok {
		close(waitCh)
		delete(e.dimSwitchChs, height)
	}

	for _, info := range e.handoffs.Run(beacon.EpochMax, height) {
		ctx, cancel := context.WithCancelCause(context.Background())
		info.cancel = cancel

		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.handoff(ctx, info.status, dimSwitchCh)
		}()
	}
}

// Stop stops all handoffs currently in progress and waits for them to complete.
func (e *handoffExecutor) Stop() {
	cause := fmt.Errorf("stopped")
	e.handoffs.Stop(cause)
	e.wg.Wait()
}

// Clear removes queued handoffs that didn't complete in time,
// while retaining those that are still pending.
func (e *handoffExecutor) Clear(epoch beacon.EpochTime) {
	e.handoffs.Clear(epoch)
}

// Cancel sends stop signal to handoffs in progress which are not allowed
// to run anymore.
func (e *handoffExecutor) Cancel(epoch beacon.EpochTime) {
	cause := fmt.Errorf("handoff ended: epoch %d", epoch)
	e.handoffs.Cancel(epoch, cause)
}

// handoff tries to execute the handoff and submits a confirmation upon
// successful completion.
func (e *handoffExecutor) handoff(ctx context.Context, status *churp.Status, dimSwitchCh chan struct{}) {
	kind := status.HandoffKind()
	oldCommittee := status.Committee
	newCommittee := maps.Keys(status.Applications)

	e.logger.Info("starting handoff",
		"id", status.ID,
		"epoch", status.NextHandoff,
		"threshold", status.Threshold,
		"kind", kind,
		"old committee", oldCommittee,
		"new committee", newCommittee,
	)

	// Prioritize nodes depending on the number of failed requests.
	// Higher is better.
	priorities := make(map[signature.PublicKey]int)
	for _, id := range oldCommittee {
		priorities[id] = 0
	}
	for _, id := range newCommittee {
		priorities[id] = 0
	}

	// The local node should have the highest priority, as we always want
	// to fetch from it first.
	priorities[e.kmWorker.nodeID] = 100

	// Share reduction (optional).
	if kind == churp.HandoffKindCommitteeChanged {
		if err := e.shareReduction(ctx, status, oldCommittee, priorities); err != nil {
			e.logger.Warn("failed to do share reduction",
				"id", status.ID,
				"epoch", status.NextHandoff,
				"err", err,
			)
			return
		}

		// No need to wait between share reduction and proactivization,
		// as these two stages are independent.
	}

	// Proactivization.
	if err := e.proactivization(ctx, status, newCommittee, priorities); err != nil {
		e.logger.Warn("failed to do proactivization",
			"id", status.ID,
			"epoch", status.NextHandoff,
			"err", err,
		)
		return
	}

	// Full share distribution (optional).
	if kind == churp.HandoffKindCommitteeChanged {
		// Wait few blocks, as share distribution can only start once enough
		// nodes complete proactivization.
		select {
		case <-dimSwitchCh:
		case <-ctx.Done():
			return
		}

		if err := e.shareDistribution(ctx, status, newCommittee, priorities); err != nil {
			e.logger.Warn("failed to do share distribution",
				"id", status.ID,
				"epoch", status.NextHandoff,
				"err", err,
			)
			return
		}
	}

	// Confirmation.
	if err := e.submitConfirmation(ctx, status); err != nil {
		e.logger.Warn("failed to submit confirmation",
			"id", status.ID,
			"epoch", status.NextHandoff,
			"err", err,
		)
	}
}

// shareReduction tries to fetch switch points for share reduction from
// the given nodes.
func (e *handoffExecutor) shareReduction(ctx context.Context, status *churp.Status, nodeIDs []signature.PublicKey, priorities map[signature.PublicKey]int) error {
	return e.fetch(ctx, status, nodeIDs, priorities, "share reduction", churp.RPCMethodShareReduction)
}

// proactivization tries to fetch bivariate shares from the given nodes.
func (e *handoffExecutor) proactivization(ctx context.Context, status *churp.Status, nodeIDs []signature.PublicKey, priorities map[signature.PublicKey]int) error {
	return e.fetch(ctx, status, nodeIDs, priorities, "proactivization", churp.RPCMethodProactivization)
}

// shareDistribution tries to fetch switch points for share distribution from
// the given nodes.
func (e *handoffExecutor) shareDistribution(ctx context.Context, status *churp.Status, nodeIDs []signature.PublicKey, priorities map[signature.PublicKey]int) error {
	return e.fetch(ctx, status, nodeIDs, priorities, "share distribution", churp.RPCMethodShareDistribution)
}

// fetch requests the enclave to fetch switch points or bivariate shares
// from the given nodes.
func (e *handoffExecutor) fetch(
	ctx context.Context,
	status *churp.Status,
	nodeIDs []signature.PublicKey,
	priorities map[signature.PublicKey]int,
	stage string,
	method string,
) error {
	remainingNodeIDs := make(map[signature.PublicKey]struct{})
	for _, id := range nodeIDs {
		remainingNodeIDs[id] = struct{}{}
	}

	return retry(ctx, func(attempt int) error {
		nodeIDs := selectNodes(remainingNodeIDs, priorities)

		e.logger.Info(fmt.Sprintf("trying to do %s", stage),
			"id", status.ID,
			"epoch", status.NextHandoff,
			"node_ids", nodeIDs,
			"attempt", attempt,
		)

		rsp, err := e.tryFetch(ctx, status, nodeIDs, method)
		if err != nil {
			e.logger.Warn(fmt.Sprintf("failed to do %s", stage),
				"id", status.ID,
				"epoch", status.NextHandoff,
				"attempt", attempt,
				"err", err,
			)
			return fmt.Errorf("failed to do %s: %w", stage, err)
		}

		e.logger.Info(fmt.Sprintf("%s status", stage),
			"id", status.ID,
			"epoch", status.NextHandoff,
			"attempt", attempt,
			"completed", rsp.Completed,
			"succeeded", rsp.Succeeded,
			"failed", rsp.Failed,
		)

		// Update priorities.
		for _, id := range rsp.Succeeded {
			priorities[id]++
		}
		for _, id := range rsp.Failed {
			priorities[id]--
		}

		// Stop when enough nodes respond.
		if rsp.Completed {
			return nil
		}

		// Retry with the rest of the nodes.
		for _, id := range rsp.Succeeded {
			delete(remainingNodeIDs, id)
		}

		return fmt.Errorf("failed to complete %s", stage)
	})
}

// tryFetch tries to request the enclave to fetch switch points or bivariate
// shares from the given nodes.
func (e *handoffExecutor) tryFetch(
	ctx context.Context,
	status *churp.Status,
	nodeIDs []signature.PublicKey,
	method string,
) (*churp.FetchResponse, error) {
	req := churp.FetchRequest{
		Identity: churp.Identity{
			ID:        status.ID,
			RuntimeID: e.kmWorker.runtimeID,
		},
		Epoch:   status.NextHandoff,
		NodeIDs: nodeIDs,
	}
	var rsp churp.FetchResponse
	if err := e.kmWorker.callEnclaveLocal(ctx, method, req, &rsp); err != nil {
		return nil, err
	}

	return &rsp, nil
}

// submitConfirmation tries to submit a confirmation, retrying if transaction
// fails.
func (e *handoffExecutor) submitConfirmation(ctx context.Context, status *churp.Status) error {
	return retry(ctx, func(attempt int) error {
		e.logger.Info("trying to submit confirmation",
			"id", status.ID,
			"epoch", status.NextHandoff,
			"attempt", attempt,
		)

		err := e.trySubmitConfirmation(ctx, status)
		if err != nil {
			e.logger.Debug("failed to submit confirmation",
				"id", status.ID,
				"epoch", status.NextHandoff,
				"attempt", attempt,
				"err", err,
			)
			return err
		}

		return nil
	})
}

// trySubmitConfirmation tries to submit confirmation.
func (e *handoffExecutor) trySubmitConfirmation(ctx context.Context, status *churp.Status) error {
	// Ask enclave to confirm handoff.
	req := churp.HandoffRequest{
		Identity: churp.Identity{
			ID:        status.ID,
			RuntimeID: e.kmWorker.runtimeID,
		},
		Epoch: status.NextHandoff,
	}
	var rsp churp.SignedConfirmationRequest
	if err := e.kmWorker.callEnclaveLocal(ctx, churp.RPCMethodConfirm, req, &rsp); err != nil {
		return fmt.Errorf("failed to prepare confirmation request: %w", err)
	}

	// Validate the signature.
	rak, err := e.kmWorker.runtimeAttestationKey()
	if err != nil {
		return err
	}
	if err = rsp.VerifyRAK(rak); err != nil {
		return fmt.Errorf("failed to verify confirmation request: %w", err)
	}

	// Publish transaction.
	tx := churp.NewConfirmTx(0, nil, &rsp)
	if err = consensus.SignAndSubmitTx(ctx, e.kmWorker.commonWorker.Consensus, e.kmWorker.commonWorker.Identity.NodeSigner, tx); err != nil {
		return err
	}

	return nil
}

// handoffFinisher completes handoffs upon completion.
type handoffFinisher struct {
	logger *logging.Logger

	wg sync.WaitGroup

	// kmWorker provides access to the common key manager services.
	kmWorker *Worker

	// statuses holds the latest statuses.
	statuses map[uint8]*churp.Status

	// cancels stores functions to cancel ongoing finalizations.
	cancels map[uint8]context.CancelCauseFunc
}

// newHandoffFinisher creates a new handoff finisher.
func newHandoffFinisher(kmWorker *Worker) *handoffFinisher {
	return &handoffFinisher{
		logger:   logging.GetLogger("worker/keymanager/churp/finisher"),
		kmWorker: kmWorker,
		statuses: make(map[uint8]*churp.Status),
		cancels:  make(map[uint8]context.CancelCauseFunc),
	}
}

// Stop stops all handoffs currently in progress and waits for them to complete.
func (f *handoffFinisher) Stop() {
	cause := fmt.Errorf("stopped")
	for _, cancel := range f.cancels {
		cancel(cause)
	}
	f.wg.Wait()
}

// Finalize notifies the enclave if the last handoff completed/failed.
func (f *handoffFinisher) Finalize(status *churp.Status) {
	lastStatus, ok := f.statuses[status.ID]
	f.statuses[status.ID] = status
	if !ok {
		return
	}

	if lastStatus.Handoff == status.Handoff && lastStatus.NextHandoff == status.NextHandoff {
		return
	}

	if cancel, ok := f.cancels[status.ID]; ok {
		cancel(fmt.Errorf("new handoff"))
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	f.cancels[status.ID] = cancel

	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.finalizeHandoff(ctx, status)
	}()
}

// finalizeHandoff tries to finalize a completed handoff.
func (f *handoffFinisher) finalizeHandoff(ctx context.Context, status *churp.Status) {
	f.logger.Info("trying to finalize handoff",
		"id", status.ID,
		"handoff", status.Handoff,
		"next_handoff", status.NextHandoff,
	)

	// Ask enclave to finalize the handoff.
	req := churp.HandoffRequest{
		Identity: churp.Identity{
			ID:        status.ID,
			RuntimeID: f.kmWorker.runtimeID,
		},
		Epoch: status.Handoff,
	}
	var rsp protocol.Empty
	if err := f.kmWorker.callEnclaveLocal(ctx, churp.RPCMethodFinalize, req, &rsp); err != nil {
		f.logger.Info("failed to finalize handoff",
			"id", status.ID,
			"epoch", status.Handoff,
			"err", err,
		)
	}
}

// nodeWatcher is responsible for maintaining a list of applicants.
type nodeWatcher struct {
	logger *logging.Logger

	mu sync.RWMutex

	// peerMap is used to translate key manager peer IDs to node IDs.
	peerMap *PeerMap

	// applicants tracks the number of schemes in which nodes want to form
	// new committees.
	applicants map[signature.PublicKey]int

	// applicantsPerScheme tracks which nodes want to form a new committee
	// in a specific scheme.
	applicantsPerScheme map[uint8][]signature.PublicKey
}

// newNodeWatcher creates a new node watcher.
func newNodeWatcher(peerMap *PeerMap) *nodeWatcher {
	return &nodeWatcher{
		logger:              logging.GetLogger("worker/keymanager/churp/watcher"),
		peerMap:             peerMap,
		applicants:          make(map[signature.PublicKey]int),
		applicantsPerScheme: make(map[uint8][]signature.PublicKey),
	}
}

// Update updates the list of applicants based on the provided status.
func (w *nodeWatcher) Update(status *churp.Status) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Remove current nodes.
	if nodeIDs, ok := w.applicantsPerScheme[status.ID]; ok {
		for _, nodeID := range nodeIDs {
			if w.applicants[nodeID] == 1 {
				delete(w.applicants, nodeID)
			} else {
				w.applicants[nodeID]--
			}
		}
	}

	// Add new ones.
	for nodeID := range status.Applications {
		w.applicants[nodeID]++
	}

	// Remember which nodes were added.
	w.applicantsPerScheme[status.ID] = maps.Keys(status.Applications)
}

// HasApplied returns true if the given peer has applied to form a committee
// in at least one tracked scheme.
func (w *nodeWatcher) HasApplied(peerID core.PeerID) bool {
	nodeID, ok := w.peerMap.NodeID(peerID)
	if !ok {
		return false
	}

	w.mu.RLock()
	defer w.mu.RUnlock()

	if _, ok := w.applicants[nodeID]; !ok {
		return false
	}
	return true
}

// retry attempts to execute the given function until it succeeds,
// reaches the maximum number of attempts, or the context expires.
func retry(ctx context.Context, fn func(int) error) error {
	bo := cmnBackoff.NewExponentialBackOff()
	bo.InitialInterval = retryInitialInterval
	bo.Reset()

	ticker := backoff.NewTicker(bo)

	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err = fn(attempt); err == nil {
			return nil
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ctx.Err(), context.Cause(ctx))
		}
	}

	return fmt.Errorf("%w: reached maximum number of attempts", err)
}

// selectNodes selects the top n nodes based on their priorities.
func selectNodes(nodeIDs map[signature.PublicKey]struct{}, priorities map[signature.PublicKey]int) []signature.PublicKey {
	nodes := maps.Keys(nodeIDs)

	// Shuffle nodes to get a random order.
	rand.Shuffle(len(nodes), func(i, j int) {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	})

	// And then sort them to move nodes with higher priority upfront.
	sort.Slice(nodes, func(i, j int) bool {
		return priorities[nodes[i]] > priorities[nodes[j]]
	})

	return nodes
}

// TaskInfo contains details about a scheduled task.
type TaskInfo struct {
	// status is the consensus status of the CHURP scheme.
	status *churp.Status

	// height denotes the minimum block height required for the task to run.
	height int64

	// index specifies the position in the task queue, or -1 if not queued.
	index int

	// cancel is a function to cancel the task if it's in progress, otherwise,
	// it's nil.
	cancel context.CancelCauseFunc
}

func newTaskInfo(status *churp.Status, height int64) *TaskInfo {
	return &TaskInfo{
		status: status,
		height: height,
		index:  -1,
		cancel: nil,
	}
}

// TaskQueue represents a queue of tasks.
type TaskQueue struct {
	// queue contains tasks waiting to be processed, ordered by the next handoff
	// epoch and minimum block height required for the task to run.
	queue taskQueue

	// running contains tasks that are currently in progress.
	running map[uint8]*TaskInfo

	// tasks contains both queued and running tasks.
	tasks map[uint8]*TaskInfo
}

func newTaskQueue() TaskQueue {
	return TaskQueue{
		queue:   make([]*TaskInfo, 0),
		running: make(map[uint8]*TaskInfo),
		tasks:   make(map[uint8]*TaskInfo),
	}
}

// Get returns the information about a task with the given identifier.
func (s *TaskQueue) Get(churpID uint8) (*TaskInfo, bool) {
	info, ok := s.tasks[churpID]
	return info, ok
}

// Add queues a task to the task queue.
func (s *TaskQueue) Add(info *TaskInfo) {
	s.tasks[info.status.ID] = info
	heap.Push(&s.queue, info)
}

// Remove removes the given task from the task queue and stops it
// if it is running.
func (s *TaskQueue) Remove(info *TaskInfo, cause error) {
	if info == nil {
		return
	}

	if info.cancel != nil {
		info.cancel(cause)
		delete(s.running, info.status.ID)
	}

	if info.index != -1 {
		heap.Remove(&s.queue, info.index)
	}

	delete(s.tasks, info.status.ID)
}

// Run returns all scheduled tasks with the next handoff epoch and the minimum
// block height not exceeding the given values, and marks them as running.
func (s *TaskQueue) Run(epoch beacon.EpochTime, height int64) []*TaskInfo {
	var infos []*TaskInfo

	for {
		if len(s.queue) == 0 {
			break
		}
		info := s.queue.Peek().(*TaskInfo)
		if info.status.NextHandoff > epoch || info.height > height {
			break
		}
		_ = heap.Pop(&s.queue)

		s.running[info.status.ID] = info

		infos = append(infos, info)
	}

	return infos
}

// Stop cancels and removes all running tasks.
func (s *TaskQueue) Stop(cause error) {
	for _, info := range s.running {
		info.cancel(cause)
		delete(s.tasks, info.status.ID)
	}
	clear(s.running)
}

// Clear removes all scheduled tasks with the next handoff epoch
// smaller than the given value.
func (s *TaskQueue) Clear(epoch beacon.EpochTime) {
	for {
		if len(s.queue) == 0 {
			return
		}
		info := s.queue.Peek().(*TaskInfo)
		if info.status.NextHandoff >= epoch {
			return
		}
		_ = heap.Pop(&s.queue)
	}
}

// Cancel cancels and removes all running tasks with the next handoff epoch
// smaller than the given value.
func (s *TaskQueue) Cancel(epoch beacon.EpochTime, cause error) {
	for id, info := range s.running {
		if info.status.NextHandoff < epoch {
			continue
		}
		info.cancel(cause)
		delete(s.running, id)
		delete(s.tasks, info.status.ID)
	}
}

// Ensure that the task queue implements heap.Interface.
var _ heap.Interface = (*taskQueue)(nil)

// taskQueue is a queue of tasks ordered by the time they are allowed to run.
type taskQueue []*TaskInfo

// Len implements heap.Interface.
func (q taskQueue) Len() int {
	return len(q)
}

// Less implements heap.Interface.
func (q taskQueue) Less(i, j int) bool {
	if q[i].status.NextHandoff != q[j].status.NextHandoff {
		return q[i].status.NextHandoff < q[j].status.NextHandoff
	}
	return q[i].height < q[j].height
}

// Swap implements heap.Interface.
func (q taskQueue) Swap(i, j int) {
	q[i].index = j
	q[j].index = i
	q[i], q[j] = q[j], q[i]
}

// Push implements heap.Interface.
func (q *taskQueue) Push(x any) {
	x.(*TaskInfo).index = len(*q)
	*q = append(*q, x.(*TaskInfo))
}

// Pop implements heap.Interface.
func (q *taskQueue) Pop() any {
	old := *q
	n := len(old)
	x := old[n-1]
	x.index = -1
	old[n-1] = nil
	*q = old[0 : n-1]
	return x
}

// Peek returns the smallest element in the heap.
func (q taskQueue) Peek() any {
	switch n := len(q); n {
	case 0:
		return nil
	default:
		return q[0]
	}
}
