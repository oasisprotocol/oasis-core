package committee

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
)

// Watcher is the committee watcher interface.
type Watcher interface {
	// Nodes returns a node descriptor lookup interface that watches all nodes in the committee.
	Nodes() NodeDescriptorLookup

	// EpochTransition signals an epoch transition to the committee watcher.
	EpochTransition(ctx context.Context, height int64) error
}

type committeeWatcher struct { // nolint: maligned
	nw        NodeDescriptorWatcher
	scheduler scheduler.Backend

	runtimeID common.Namespace
	kind      scheduler.CommitteeKind

	filters   []Filter
	autoEpoch bool

	logger *logging.Logger
}

func (cw *committeeWatcher) Nodes() NodeDescriptorLookup {
	return cw.nw
}

func (cw *committeeWatcher) EpochTransition(ctx context.Context, height int64) error {
	if cw.autoEpoch {
		return fmt.Errorf("committee: manual epoch transition not allowed when automatic is enabled")
	}

	// Clear all previous nodes.
	cw.nw.Reset()

	// TODO: Support request for only a specific committee kind.
	committees, err := cw.scheduler.GetCommittees(ctx, &scheduler.GetCommitteesRequest{
		RuntimeID: cw.runtimeID,
		Height:    height,
	})
	if err != nil {
		return fmt.Errorf("committee: unable to fetch committees: %w", err)
	}

	var committee *scheduler.Committee
	for _, c := range committees {
		if c.Kind != cw.kind {
			continue
		}
		committee = c
		break
	}
	if committee == nil {
		return fmt.Errorf("committee: no committee of kind %s for runtime %s", cw.kind, cw.runtimeID)
	}

	return cw.update(ctx, height, committee)
}

func (cw *committeeWatcher) update(ctx context.Context, version int64, committee *scheduler.Committee) (err error) {
	defer func() {
		// Make sure to not watch any nodes in case we fail to update the committee.
		if err != nil {
			cw.nw.Reset()
		}
	}()

Members:
	for _, member := range committee.Members {
		// Filter members.
		for _, f := range cw.filters {
			if !f(member) {
				continue Members
			}
		}

		_, err := cw.nw.WatchNode(ctx, member.PublicKey)
		if err != nil {
			return fmt.Errorf("committee: failed to watch node: %w", err)
		}
	}

	// Freeze the node watcher as we will not be watching any additional nodes.
	cw.nw.Freeze(version)

	return nil
}

func (cw *committeeWatcher) watchCommittees(ctx context.Context, ch <-chan *scheduler.Committee, sub pubsub.ClosableSubscription) {
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case c := <-ch:
			if c == nil {
				return
			}
			if c.RuntimeID != cw.runtimeID {
				continue
			}
			if c.Kind != cw.kind {
				continue
			}

			// Clear all previous nodes.
			cw.nw.Reset()

			if err := cw.update(ctx, int64(c.ValidFor), c); err != nil {
				cw.logger.Error("failed to update committee",
					"err", err,
				)
			}
		}
	}
}

// WatcherOption is an option for NewWatcher.
type WatcherOption func(cw *committeeWatcher)

// AutomaticEpochTransitions is an option for enabling automatic epoch transitions in the commitee
// watcher. Committees will be updated whenever the scheduler elects new committees.
func WithAutomaticEpochTransitions() WatcherOption {
	return func(cw *committeeWatcher) {
		cw.autoEpoch = true
	}
}

// Filter is filter function for the committee watcher. It should return false for any members which
// should be excluded.
type Filter func(*scheduler.CommitteeNode) bool

// WithFilter is an option that adds a given filter to the committee watcher.
func WithFilter(f Filter) WatcherOption {
	return func(cw *committeeWatcher) {
		cw.filters = append(cw.filters, f)
	}
}

// NewWatcher creates a new committee watcher.
func NewWatcher(
	ctx context.Context,
	scheduler scheduler.Backend,
	registry registry.Backend,
	runtimeID common.Namespace,
	kind scheduler.CommitteeKind,
	options ...WatcherOption,
) (Watcher, error) {
	nw, err := NewNodeDescriptorWatcher(ctx, registry)
	if err != nil {
		return nil, fmt.Errorf("committee: failed to create node descriptor watcher: %w", err)
	}

	cw := &committeeWatcher{
		nw:        nw,
		scheduler: scheduler,
		runtimeID: runtimeID,
		kind:      kind,
		logger:    logging.GetLogger("runtime/committee/watcher"),
	}

	for _, o := range options {
		o(cw)
	}

	// If configured, subscribe to committee updates.
	if cw.autoEpoch {
		ch, sub, err := scheduler.WatchCommittees(ctx)
		if err != nil {
			return nil, fmt.Errorf("committee: failed to watch committees: %w", err)
		}

		go cw.watchCommittees(ctx, ch, sub)
	}

	return cw, nil
}
