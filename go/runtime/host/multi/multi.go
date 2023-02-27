// Package multi implements support for a runtime host aggregator that
// handles multiplexing multiple instances of other runtime hosts, to
// enable seamless transitions between versions.
package multi

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

var (
	// ErrNoActiveVersion is the error returned if there is no active version.
	ErrNoActiveVersion = errors.New("runtime/host/multi: no active version")

	// ErrNoSuchVersion is the error returned if the requested version is unknown.
	ErrNoSuchVersion = errors.New("runtime/host/multi: no such version")
)

type aggregatedHost struct {
	host host.Runtime

	ch               <-chan *host.Event
	sub              pubsub.ClosableSubscription
	stopCh           chan struct{}
	stoppedCh        chan struct{}
	stopDiscardCh    chan struct{}
	stoppedDiscardCh chan *host.Event

	version version.Version
}

func (ah *aggregatedHost) startDiscard() {
	go func() {
		var startedEv *host.Event
		defer func() {
			// In case we observed a started event, forward it.
			ah.stoppedDiscardCh <- startedEv
			close(ah.stoppedDiscardCh)
		}()

		for {
			select {
			case <-ah.stopDiscardCh:
				return
			case ev := <-ah.ch:
				switch {
				case ev.Started != nil:
					// Store the last started event.
					startedEv = ev
				case ev.Stopped != nil:
					// Clear out if any stopped event received.
					startedEv = nil
				case ev.Updated != nil && startedEv != nil:
					// Make sure the started event's CapabilityTEE is always the latest one.
					startedEv.Started.CapabilityTEE = ev.Updated.CapabilityTEE
				}
			}
		}
	}()
}

func (ah *aggregatedHost) stopDiscard(agg *Aggregate) {
	close(ah.stopDiscardCh)
	ev := <-ah.stoppedDiscardCh

	// Propagate captured started event.
	if ev != nil && agg != nil {
		agg.notifier.Broadcast(ev)
	}
}

func (ah *aggregatedHost) startPassthrough(agg *Aggregate) {
	go func() {
		defer close(ah.stoppedCh)
		for {
			select {
			case <-ah.stopCh:
				return
			case ev := <-ah.ch:
				agg.notifier.Broadcast(ev)
			}
		}
	}()
}

func (ah *aggregatedHost) stopPassthrough() {
	close(ah.stopCh)
	<-ah.stoppedCh
}

// Aggregate is an aggregated runtime consisting of multiple instances of
// the same runtime (by ID), all with different versions.
type Aggregate struct {
	l sync.RWMutex

	id     common.Namespace
	logger *logging.Logger

	hosts  map[version.Version]*aggregatedHost
	active *aggregatedHost
	next   *aggregatedHost

	notifier *pubsub.Broker
}

// ID implements host.Runtime.
func (agg *Aggregate) ID() common.Namespace {
	return agg.id
}

// GetInfo implements host.Runtime.
func (agg *Aggregate) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	agg.l.RLock()
	defer agg.l.RUnlock()

	if agg.active == nil {
		return nil, ErrNoActiveVersion
	}
	return agg.active.host.GetInfo(ctx)
}

// GetCapabilityTEE implements host.Runtime.
func (agg *Aggregate) GetCapabilityTEE(ctx context.Context) (*node.CapabilityTEE, error) {
	agg.l.RLock()
	defer agg.l.RUnlock()

	if agg.active == nil {
		return nil, ErrNoActiveVersion
	}
	return agg.active.host.GetCapabilityTEE(ctx)
}

// Call implements host.Runtime.
func (agg *Aggregate) Call(ctx context.Context, body *protocol.Body) (rsp *protocol.Body, err error) {
	callFn := func() error {
		agg.l.RLock()
		if agg.active == nil {
			agg.l.RUnlock()
			return ErrNoActiveVersion
		}
		host := agg.active.host
		// Take care to release lock before calling into the runtime as otherwise this could lead
		// to a deadlock in case the runtime makes a call that acquires the cross node lock and at
		// the same time SetVersion is being called to update the version with the cross node lock
		// acquired.
		agg.l.RUnlock()

		rsp, err = host.Call(ctx, body)
		if err != nil {
			// All protocol-level errors are permanent.
			return backoff.Permanent(err)
		}
		return nil
	}

	// Retry call in case the runtime is not yet ready.
	err = backoff.Retry(callFn, backoff.WithContext(cmnBackoff.NewExponentialBackOff(), ctx))
	return
}

// UpdateCapabilityTEE implements host.Runtime.
func (agg *Aggregate) UpdateCapabilityTEE(ctx context.Context) error {
	agg.l.RLock()
	defer agg.l.RUnlock()

	var errs *multierror.Error
	if agg.active != nil {
		err := agg.active.host.UpdateCapabilityTEE(ctx)
		errs = multierror.Append(errs, err)
	}
	if agg.next != nil {
		err := agg.next.host.UpdateCapabilityTEE(ctx)
		errs = multierror.Append(errs, err)
	}
	return errs.ErrorOrNil()
}

// WatchEvents implements host.Runtime.
func (agg *Aggregate) WatchEvents(ctx context.Context) (<-chan *host.Event, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *host.Event)
	sub := agg.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

// Start implements host.Runtime.
func (agg *Aggregate) Start() error {
	agg.l.RLock()
	defer agg.l.RUnlock()

	// This is "ok", sort of, though maybe this should fail.
	if agg.active == nil {
		return nil
	}

	return agg.active.host.Start()
}

// Abort implements host.Runtime.
func (agg *Aggregate) Abort(ctx context.Context, force bool) error {
	agg.l.RLock()
	defer agg.l.RUnlock()

	if agg.active == nil {
		return ErrNoActiveVersion
	}
	return agg.active.host.Abort(ctx, force)
}

// Stop implements host.Runtime.
func (agg *Aggregate) Stop() {
	agg.l.Lock()
	defer agg.l.Unlock()

	// This is only used for teardown, so while not great, it is ok that
	// this leaves the notifier lying around.

	agg.stopActiveLocked()
	agg.stopNextLocked()
}

// GetVersion retrieves the runtime host for the specified version.
func (agg *Aggregate) GetVersion(ctx context.Context, version version.Version) (host.Runtime, error) {
	agg.l.RLock()
	defer agg.l.RUnlock()

	host := agg.hosts[version]
	if host == nil {
		return nil, ErrNoSuchVersion
	}
	// Only allow fetching either the active or next versions.
	if host != agg.active && host != agg.next {
		return nil, ErrNoSuchVersion
	}
	return host.host, nil
}

// SetVersion sets the active and next runtime versions.  This routine will:
//   - Do nothing if the active version is already the requested version.
//   - Unconditionally tear down the currently active version (via Stop()).
//   - Start the newly active version if it exists.
//   - Do nothing if the next version is already the requested version.
//   - Start the next version if it exists.
func (agg *Aggregate) SetVersion(ctx context.Context, active version.Version, next *version.Version) error {
	agg.l.Lock()
	defer agg.l.Unlock()

	agg.logger.Info("set version",
		"id", agg.ID(),
		"active", active,
		"next", next,
	)

	if err := agg.setActiveVersionLocked(ctx, active); err != nil {
		return err
	}
	if err := agg.setNextVersionLocked(ctx, next); err != nil {
		return err
	}
	return nil
}

func (agg *Aggregate) setActiveVersionLocked(ctx context.Context, version version.Version) error {
	// Contract: agg.l already locked for write.

	next := agg.hosts[version]

	// Ensure that we know about the new version.
	if next == nil {
		agg.logger.Error("SetVersion: unknown version",
			"id", agg.ID(),
			"version", version,
		)

		// If we don't, tear down the old version anyway.
		agg.stopActiveLocked()
		return ErrNoSuchVersion
	}

	// If there already is an active version...
	if agg.active != nil {
		// And it is the same as the requested one, we are done.
		if next == agg.active {
			return nil
		}

		// Otherwise tear it down.
		agg.stopActiveLocked()
	}

	// Get ready to spin up the new runtime.
	if agg.next == next {
		// This is the next active version which has already been started in advance. Clear out the
		// currently active next version and stop discarding events.
		agg.next = nil
		next.stopDiscard(agg) // Forward any captured started events.
	} else {
		host := next.host
		if err := host.Start(); err != nil {
			// Do not bail, this can't actually fail in practice because
			// the part that does all the work is async.  Log something.
			agg.logger.Error("SetVersion: failed to start sub-host",
				"err", err,
				"id", agg.ID(),
				"version", version,
			)
		}
	}

	// Assume that the caller is ok with SetVersion acting as a Stop+Start
	// and just start propagating events immediately.
	next.startPassthrough(agg)

	// Active runtime swapped out, update the state and return.
	agg.active = next

	return nil
}

func (agg *Aggregate) stopActiveLocked() {
	// Contract: agg.l already locked for write.

	if agg.active == nil {
		return
	}

	agg.logger.Debug("stopActiveLocked",
		"id", agg.ID(),
		"version", agg.active.version,
	)

	// Remove the runtime's event channel from the pubsub aggregator
	// before halting the previous active version so that we can catch
	// the host.StoppedEvent and not propagate it if requested to
	// do so.
	ah := agg.active
	ah.stopPassthrough()

	// Terminate the active instance.
	ah.host.Stop()

	// Wait for a host.StoppedEvent, while passing events through to the
	// aggregator.
	for {
		ev := <-ah.ch
		agg.notifier.Broadcast(ev) // Propagate
		if ev.Stopped == nil {
			continue
		}
		agg.logger.Debug("stopActiveLocked: stopped old sub-host",
			"id", agg.ID(),
			"version", agg.active.version,
		)
		break
	}

	// Close off the subscription, invalidate the old sub-host.
	agg.active.sub.Close()
	agg.hosts[agg.active.version] = nil
	agg.active = nil
}

func (agg *Aggregate) setNextVersionLocked(ctx context.Context, maybeVersion *version.Version) error {
	// Contract: agg.l already locked for write.

	// The next version could become unscheduled, in this case tear it down.
	if maybeVersion == nil {
		agg.stopNextLocked()
		return nil
	}
	version := *maybeVersion

	next := agg.hosts[version]

	// Ensure that we know about the next version.
	if next == nil {
		agg.logger.Warn("unsupported next version",
			"id", agg.ID(),
			"version", version,
		)
		// Active version must be unaffected.
		return ErrNoSuchVersion
	}

	// Ensure next version is not the same as the active version.
	if agg.active != nil && next == agg.active {
		return nil
	}

	// If there already is a next version...
	if agg.next != nil {
		// If it is the same as the requested one, we are done.
		if next == agg.next {
			return nil
		}

		// Warn in case the next version is changed but the previous one was not activated yet.
		agg.logger.Warn("overwriting next version without activation",
			"id", agg.ID(),
			"version", version,
			"previous_version", agg.next.version,
		)
		agg.stopNextLocked()
	}

	// Start the next version.
	if err := next.host.Start(); err != nil {
		// Do not bail, this can't actually fail in practice because
		// the part that does all the work is async.  Log something.
		agg.logger.Error("failed to start next version sub-host",
			"err", err,
			"id", agg.ID(),
			"version", version,
		)
	}

	// Start discarding events.
	next.startDiscard()

	// Update the next version.
	agg.next = next

	// Notify subscribers that configuration has changed.
	agg.notifier.Broadcast(&host.Event{ConfigUpdated: &host.ConfigUpdatedEvent{}})

	return nil
}

func (agg *Aggregate) stopNextLocked() {
	// Contract: agg.l already locked for write.

	if agg.next == nil {
		return
	}

	agg.logger.Debug("stopNextLocked",
		"id", agg.ID(),
		"version", agg.next.version,
	)

	ah := agg.next
	ah.stopDiscard(nil) // Drop any captured started events.

	// Terminate the next instance.
	ah.host.Stop()

	// Close off the subscription, invalidate the old sub-host.
	ah.sub.Close()
	agg.hosts[ah.version] = nil
	agg.next = nil

	// Notify subscribers that configuration has changed.
	agg.notifier.Broadcast(&host.Event{ConfigUpdated: &host.ConfigUpdatedEvent{}})
}

// New returns a new aggregated runtime.  The runtimes provided must be
// freshly provisioned (ie: Start() must not have been called).
func New(
	ctx context.Context,
	id common.Namespace,
	rts map[version.Version]host.Runtime,
) (host.Runtime, error) {
	if len(rts) == 0 {
		return nil, fmt.Errorf("runtime/host/multi: no sub-runtimes")
	}

	agg := &Aggregate{
		id:       id,
		logger:   logging.GetLogger("runtime/host/multi"),
		hosts:    make(map[version.Version]*aggregatedHost),
		notifier: pubsub.NewBroker(false),
	}

	for version, rt := range rts {
		if rt.ID() != id {
			return nil, fmt.Errorf("runtime/host/multi: sub-runtime mismatch: got '%s', expected '%s'",
				rt.ID().String(),
				id.String(),
			)
		}
		if agg.hosts[version] != nil {
			return nil, fmt.Errorf("runtime/host/multi: duplicate sub-runtime version: %v", version)
		}

		ch, sub, err := rt.WatchEvents(ctx)
		if err != nil {
			return nil, fmt.Errorf("runtime/host/multi: failed to subscribe to sub-runtime events: %w", err)
		}

		ah := &aggregatedHost{
			host:             rts[version],
			ch:               ch,
			sub:              sub,
			stopCh:           make(chan struct{}),
			stoppedCh:        make(chan struct{}),
			stopDiscardCh:    make(chan struct{}),
			stoppedDiscardCh: make(chan *host.Event),
			version:          version,
		}
		agg.hosts[version] = ah
	}

	return agg, nil
}
