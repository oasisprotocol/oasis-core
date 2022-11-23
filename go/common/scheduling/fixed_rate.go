package scheduling

import (
	"context"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
)

type fixedRateTask struct {
	name string
	fn   func(ctx context.Context) error
}

var _ Scheduler = (*fixedRateScheduler)(nil)

// fixedRateScheduler executes tasks consecutively after an initial delay, and repeats them
// at regular intervals.
type fixedRateScheduler struct {
	logger *logging.Logger

	delay    time.Duration // Initial time delay before first execution.
	interval time.Duration // Time interval between repetitions.

	startOne cmSync.One // Allows running scheduler only once at a time.

	mu    sync.Mutex
	tasks []*fixedRateTask
}

// NewFixedRateScheduler creates a new fixed rate scheduler.
//
// The interval must be greater than zero; if not, the scheduler will panic.
func NewFixedRateScheduler(delay time.Duration, interval time.Duration) Scheduler {
	l := logging.GetLogger("scheduler/fixed-rate")

	return &fixedRateScheduler{
		logger:   l,
		delay:    delay,
		interval: interval,
		startOne: cmSync.NewOne(),
		tasks:    make([]*fixedRateTask, 0),
	}
}

// AddTask implements Scheduler.
func (s *fixedRateScheduler) AddTask(name string, fn func(ctx context.Context) error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tasks = append(s.tasks, &fixedRateTask{
		name: name,
		fn:   fn,
	})
}

// Start implements Scheduler.
func (s *fixedRateScheduler) Start() {
	s.startOne.TryStart(s.run)
}

// Stop implements Scheduler.
func (s *fixedRateScheduler) Stop() {
	s.startOne.TryStop()
}

func (s *fixedRateScheduler) run(ctx context.Context) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	tasks := make([]*fixedRateTask, 0)

	for {
		// Add new tasks, if any.
		func() {
			s.mu.Lock()
			defer s.mu.Unlock()

			for i := len(tasks); i < len(s.tasks); i++ {
				tasks = append(tasks, s.tasks[i])
			}
		}()

		// Execute tasks consecutively.
		for _, task := range tasks {
			if err := task.fn(ctx); err != nil {
				s.logger.Error("failed to execute task",
					"err", err,
					"task", task.name,
				)
			}
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}
