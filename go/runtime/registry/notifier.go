package registry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/composite"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/multi"
)

const (
	// notifyTimeout is the maximum time to wait for a notification to be processed by the runtime.
	notifyTimeout = 10 * time.Second
)

type notifyFunc func(context.Context, host.RichRuntime)

// Queue names.
//
// Multiple queues are used so that notifications of a given kind do not block notifications of
// other kinds. All queues are created for each component independently.
const (
	queueKeyManagerStatus      = "key-manager/status"
	queueKeyManagerQuotePolicy = "key-manager/quote-policy"
	queueConsensusSync         = "consensus-sync"
)

const (
	// notifyMainQueueSize is the size of the main routing queue.
	notifyMainQueueSize = 64
	// notifyComponentQueueSize is the size of each per-component queue.
	//
	// If the queue would overflow, the oldest entry is overwritten.
	notifyComponentQueueSize = 1
)

// Notification is a notification to be sent to the component's queue.
type Notification struct {
	comp   component.ID
	queue  string
	notify notifyFunc
}

// RuntimeHostNotifier delivers notifications to the components of the given host.
type RuntimeHostNotifier struct {
	host   *composite.Host
	logger *logging.Logger

	notifyCh chan *Notification
}

// NewRuntimeHostNotifier creates a new runtime host notifier.
func NewRuntimeHostNotifier(host *composite.Host) *RuntimeHostNotifier {
	logger := logging.GetLogger("runtime/registry/notifier").
		With("runtime_id", host.ID())

	return &RuntimeHostNotifier{
		host:     host,
		logger:   logger,
		notifyCh: make(chan *Notification, notifyMainQueueSize),
	}
}

// Name returns the name of the notifier.
func (n *RuntimeHostNotifier) Name() string {
	return "runtime host notifier"
}

// Queue queues a notification for dispatching to the target component.
func (n *RuntimeHostNotifier) Queue(nf *Notification) error {
	select {
	case n.notifyCh <- nf:
		return nil
	default:
		return fmt.Errorf("notification queue is full")
	}
}

// Serve processes notifications from the queue and dispatches each to its
// corresponding component dispatcher.
func (n *RuntimeHostNotifier) Serve(ctx context.Context) error {
	n.logger.Info("starting")
	defer n.logger.Info("stopping")

	type queueID struct {
		comp  component.ID
		queue string
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	dispatchers := make(map[queueID]*notificationDispatcher)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case nf := <-n.notifyCh:
			// Route to the dispatcher for the target component.
			qid := queueID{
				comp:  nf.comp,
				queue: nf.queue,
			}

			dispatcher, ok := dispatchers[qid]
			if !ok {
				comp, exists := n.host.Component(qid.comp)
				if !exists {
					continue
				}

				dispatcher = newNotificationDispatcher(qid.comp, qid.queue, comp)
				dispatchers[qid] = dispatcher

				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := dispatcher.Serve(ctx); err != nil {
						n.logger.Error("dispatcher stopped",
							"component_id", qid.comp,
							"queue", qid.queue,
							"err", err,
						)
					}
				}()
			}

			dispatcher.Queue(nf.notify)
		}

		// Remove dispatchers for components that no longer exist.
		for qid, dispatcher := range dispatchers {
			if _, ok := n.host.Component(qid.comp); ok {
				continue
			}
			dispatcher.Stop()
			delete(dispatchers, qid)
		}
	}
}

// notificationDispatcher delivers notifications to a target component.
type notificationDispatcher struct {
	runtime host.RichRuntime
	logger  *logging.Logger

	notifyCh *channels.RingChannel
}

// newNotificationDispatcher creates a new dispatcher for the given component.
func newNotificationDispatcher(id component.ID, queue string, comp *multi.Aggregate) *notificationDispatcher {
	logger := logging.GetLogger("runtime/registry/dispatcher").
		With("runtime_id", comp.ID()).
		With("component_id", id).
		With("queue", queue)

	return &notificationDispatcher{
		runtime:  host.NewRichRuntime(comp),
		logger:   logger,
		notifyCh: channels.NewRingChannel(channels.BufferCap(notifyComponentQueueSize)),
	}
}

// Queue enqueues a notification function for the component.
func (d *notificationDispatcher) Queue(f notifyFunc) {
	d.notifyCh.In() <- f
}

// Stop signals the dispatcher to stop.
func (d *notificationDispatcher) Stop() {
	d.notifyCh.Close()
}

// Serve starts processing queued notifications for the component.
func (d *notificationDispatcher) Serve(ctx context.Context) error {
	d.logger.Info("starting")
	defer d.logger.Info("stopping")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case notify, ok := <-d.notifyCh.Out():
			if !ok {
				return nil
			}
			notify.(notifyFunc)(ctx, d.runtime)
		}
	}
}
