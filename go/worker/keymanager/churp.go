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

// submissionInfo contains details about a scheduled application submission.
type submissionInfo struct {
	// churpID represents the identifier of the CHURP scheme.
	churpID uint8

	// handoff is the epoch time of the handoff for which an application
	// is scheduled to be submitted.
	handoff beacon.EpochTime

	// height denotes the minimum block height for the submission.
	height int64

	// index specifies the position in the submission queue,
	// or -1 if not queued.
	index int

	// cancel is a function to cancel the submission if it's in progress,
	// otherwise, it's nil.
	cancel context.CancelCauseFunc
}

// submissionScheduler is responsible for generating and submitting
// application requests one epoch before handoffs.
type submissionScheduler struct {
	logger *logging.Logger

	wg sync.WaitGroup

	// kmWorker provides access to the common key manager services.
	kmWorker *Worker

	// queue contains submissions waiting to be processed, ordered by
	// the minimum block height required for the submission.
	queue SubmissionQueue

	// running contains submissions that are currently in progress.
	running map[uint8]*submissionInfo

	// submissions contains both queued and running submissions.
	submissions map[uint8]*submissionInfo
}

// newSubmissionScheduler creates a new submission scheduler.
func newSubmissionScheduler(kmWorker *Worker) *submissionScheduler {
	return &submissionScheduler{
		logger:      logging.GetLogger("worker/keymanager/churp/submissions"),
		kmWorker:    kmWorker,
		queue:       make([]*submissionInfo, 0),
		running:     make(map[uint8]*submissionInfo),
		submissions: make(map[uint8]*submissionInfo),
	}
}

// Queue schedules the given CHURP scheme for application submission,
// updating or removing the scheduled submission if already present.
func (s *submissionScheduler) Queue(status *churp.Status) {
	removeFn := func(info *submissionInfo, cause error) {
		if info.cancel != nil {
			info.cancel(cause)
			delete(s.running, status.ID)
		}
		if info.index != -1 {
			heap.Remove(&s.queue, info.index)
		}
		delete(s.submissions, status.ID)
	}

	// Stop and remove submission for the previous handoff.
	info, ok := s.submissions[status.ID]
	if ok && info.handoff < status.NextHandoff {
		removeFn(info, fmt.Errorf("new handoff"))
	}

	// Schedule submission for the current handoff.
	info, ok = s.submissions[status.ID]
	if !ok {
		epoch := status.NextHandoff - 1
		height, err := s.kmWorker.randomBlockHeight(epoch, 50)
		if err != nil {
			s.logger.Error("failed to select a random block height",
				"err", err,
			)
			return
		}

		info = &submissionInfo{
			churpID: status.ID,
			handoff: status.NextHandoff,
			height:  height,
			index:   -1,
			cancel:  nil,
		}

		s.submissions[status.ID] = info
		heap.Push(&s.queue, info)
	}

	// Stop and remove the submission if the application has already
	// been submitted or if handoffs are disabled.
	switch _, submitted := status.Applications[s.kmWorker.nodeID]; {
	case submitted:
		removeFn(info, fmt.Errorf("already submitted"))
	case status.HandoffsDisabled():
		removeFn(info, fmt.Errorf("handoffs disabled"))
	}
}

// Start starts all eligible queued submissions.
func (s *submissionScheduler) Start(ctx context.Context, height int64) {
	for {
		if len(s.queue) == 0 {
			return
		}
		info := s.queue.Peek().(*submissionInfo)
		if info.height > height {
			return
		}
		_ = heap.Pop(&s.queue)

		submitCtx, submitCancel := context.WithCancelCause(ctx)

		info.cancel = submitCancel
		s.running[info.churpID] = info

		s.wg.Add(1)
		go s.submitApplication(submitCtx, info.churpID, info.handoff)
	}
}

// Stop stops all submissions currently in progress and waits for them
// to complete.
func (s *submissionScheduler) Stop() {
	cause := fmt.Errorf("stopped")
	for _, info := range s.running {
		info.cancel(cause)
	}

	s.wg.Wait()
}

// Clear removes queued submissions that didn't complete in time,
// while retaining those that are still pending.
func (s *submissionScheduler) Clear(epoch beacon.EpochTime) {
	for {
		if len(s.queue) == 0 {
			return
		}
		info := s.queue.Peek().(*submissionInfo)
		if info.handoff > epoch {
			return
		}
		_ = heap.Pop(&s.queue)
	}
}

// Cancel sends stop signal to submissions in progress which are not allowed
// to submit applications in the given epoch.
func (s *submissionScheduler) Cancel(epoch beacon.EpochTime) {
	cause := fmt.Errorf("submissions closed: epoch %d", epoch)
	for id, churp := range s.running {
		if churp.handoff == epoch+1 {
			continue
		}
		churp.cancel(cause)
		delete(s.running, id)
	}
}

// submitApplication tries to submit an application, retrying if generation
// or transaction fails.
func (s *submissionScheduler) submitApplication(ctx context.Context, churpID uint8, handoff beacon.EpochTime) {
	defer s.wg.Done()

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

// Ensure that the submission queue implements heap.Interface.
var _ heap.Interface = (*SubmissionQueue)(nil)

// SubmissionQueue is a queue of CHURP instances ordered by the time they
// are allowed to submit an application.
type SubmissionQueue []*submissionInfo

// Len implements heap.Interface.
func (q SubmissionQueue) Len() int {
	return len(q)
}

// Less implements heap.Interface.
func (q SubmissionQueue) Less(i, j int) bool {
	return q[i].height < q[j].height
}

// Swap implements heap.Interface.
func (q SubmissionQueue) Swap(i, j int) {
	q[i].index = j
	q[j].index = i

	q[i], q[j] = q[j], q[i]
}

// Push implements heap.Interface.
func (q *SubmissionQueue) Push(x any) {
	x.(*submissionInfo).index = len(*q)
	*q = append(*q, x.(*submissionInfo))
}

// Pop implements heap.Interface.
func (q *SubmissionQueue) Pop() any {
	old := *q
	n := len(old)
	x := old[n-1]
	x.index = -1
	old[n-1] = nil
	*q = old[0 : n-1]
	return x
}

// Peek returns the smallest element in the heap.
func (q SubmissionQueue) Peek() any {
	switch l := len(q); l {
	case 0:
		return nil
	default:
		return q[l-1]
	}
}
