package keymanager

import (
	"container/heap"
	"context"
	"fmt"
	"sync"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p/core"
	"golang.org/x/exp/maps"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	workerKm "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
)

// maxSubmissionAttempts is the maximum number of attempts to submit
// an application for a handoff.
const maxSubmissionAttempts = 10

var (
	insecureChurpRPCMethods = map[string]struct{}{}
	secureChurpRPCMethods   = map[string]struct{}{}
)

// Ensure the CHURP worker implements the RPCAccessController interface.
var _ workerKm.RPCAccessController = (*churpWorker)(nil)

// churpWorker executes the CHURP protocol for the configured schemes.
type churpWorker struct {
	logger *logging.Logger

	initCh chan struct{}

	kmWorker *Worker

	mu     sync.Mutex
	churps map[uint8]*churp.Status // Guarded by mutex.

	submissions *submissionScheduler
}

// newChurpWorker constructs a new key manager CHURP worker.
func newChurpWorker(
	kmWorker *Worker,
) (*churpWorker, error) {
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
		submissions: newSubmissionScheduler(kmWorker),
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
func (w *churpWorker) Connect(context.Context, core.PeerID) bool {
	return false
}

// Authorize implements RPCAccessController interface.
func (w *churpWorker) Authorize(context.Context, string, enclaverpc.Kind, core.PeerID) error {
	return nil
}

// Initialized returns a channel that will be closed when the worker
// is initialized.
func (w *churpWorker) Initialized() <-chan struct{} {
	return w.initCh
}

// GetStatus returns the worker status.
func (w *churpWorker) GetStatus() workerKm.ChurpStatus {
	w.mu.Lock()
	defer w.mu.Unlock()

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
	w.logger.Info("starting worker")

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
			w.handleNewBlock(ctx, blk)
		case status := <-stCh:
			w.handleStatusUpdate(status)
		case <-ctx.Done():
			w.logger.Info("stopping worker")
			w.submissions.Stop()
			return
		}
	}
}

// handleNewEpoch is responsible for handling a new epoch.
func (w *churpWorker) handleNewEpoch(epoch beacon.EpochTime) {
	w.submissions.Cancel(epoch)
	w.submissions.Clear(epoch)
}

// handleNewBlock is responsible for handling a new block.
func (w *churpWorker) handleNewBlock(ctx context.Context, blk *consensus.Block) {
	w.submissions.Start(ctx, blk.Height)
}

// handleStatusUpdate is responsible for handling status update.
func (w *churpWorker) handleStatusUpdate(status *churp.Status) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Skip schemes we are not involved in.
	if status.RuntimeID != w.kmWorker.runtimeID {
		return
	}
	if _, ok := w.churps[status.ID]; !ok {
		return
	}
	w.churps[status.ID] = status

	w.logger.Debug("handle status update",
		"status", status,
	)

	w.submissions.Queue(status)
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
		logger:      logging.GetLogger("worker/keymanager/churp/submissions"),
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
		height, err := s.kmWorker.randomBlockHeight(epoch, 50)
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
func (s *submissionScheduler) Start(ctx context.Context, height int64) {
	for _, info := range s.submissions.Run(beacon.EpochMax, height) {
		submitCtx, submitCancel := context.WithCancelCause(ctx)
		info.cancel = submitCancel

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.submitApplication(submitCtx, info.status.ID, info.status.NextHandoff)
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
func (s *submissionScheduler) submitApplication(ctx context.Context, churpID uint8, handoff beacon.EpochTime) {
	ticker := backoff.NewTicker(cmnBackoff.NewExponentialBackOff())

	for attempt := 1; attempt <= maxSubmissionAttempts; attempt++ {
		err := s.trySubmitApplication(ctx, churpID, handoff)
		if err == nil {
			return
		}

		s.logger.Debug("failed to submit application",
			"id", churpID,
			"handoff", handoff,
			"attempt", attempt,
			"err", err,
		)

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// trySubmitApplication tries to submit an application.
func (s *submissionScheduler) trySubmitApplication(ctx context.Context, churpID uint8, handoff beacon.EpochTime) error {
	s.logger.Info("trying to submit application",
		"id", churpID,
		"handoff", handoff,
	)

	// Ask enclave to prepare a dealer and return signed verification matrix.
	req := churp.HandoffRequest{
		Identity: churp.Identity{
			ID:        churpID,
			RuntimeID: s.kmWorker.runtimeID,
		},
		Epoch: handoff,
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
