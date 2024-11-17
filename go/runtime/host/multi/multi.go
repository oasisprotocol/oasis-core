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

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
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

// New returns a new aggregated runtime.
func newAggregateHost(rt host.Runtime, version version.Version) *aggregatedHost {
	ch, sub := rt.WatchEvents()

	return &aggregatedHost{
		host:             rt,
		version:          version,
		ch:               ch,
		sub:              sub,
		stopCh:           make(chan struct{}),
		stoppedCh:        make(chan struct{}),
		stopDiscardCh:    make(chan struct{}),
		stoppedDiscardCh: make(chan *host.Event),
	}
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

	id common.Namespace

	hosts  map[version.Version]*aggregatedHost
	active *aggregatedHost
	next   *aggregatedHost

	notifier *pubsub.Broker

	logger *logging.Logger
}

// New returns a new aggregated runtime.
func New(id common.Namespace) *Aggregate {
	logger := logging.GetLogger("runtime/host/multi").With("runtime_id", id)

	return &Aggregate{
		id:       id,
		hosts:    make(map[version.Version]*aggregatedHost),
		active:   nil,
		next:     nil,
		notifier: pubsub.NewBroker(false),
		logger:   logger,
	}
}

// ID implements host.Runtime.
func (agg *Aggregate) ID() common.Namespace {
	return agg.id
}

func (agg *Aggregate) getActiveHost() (*aggregatedHost, error) {
	agg.l.RLock()
	defer agg.l.RUnlock()

	if agg.active == nil {
		return nil, ErrNoActiveVersion
	}
	return agg.active, nil
}

// GetActiveVersion implements host.Runtime.
func (agg *Aggregate) GetActiveVersion() (*version.Version, error) {
	agg.l.RLock()
	defer agg.l.RUnlock()

	if agg.active == nil {
		return nil, ErrNoActiveVersion
	}
	return &agg.active.version, nil
}

// GetInfo implements host.Runtime.
func (agg *Aggregate) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	active, err := agg.getActiveHost()
	if err != nil {
		return nil, err
	}
	return active.host.GetInfo(ctx)
}

// GetCapabilityTEE implements host.Runtime.
func (agg *Aggregate) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	active, err := agg.getActiveHost()
	if err != nil {
		return nil, err
	}
	return active.host.GetCapabilityTEE()
}

// shouldPropagateToNextVersion checks whether the given runtime request should also be propagated
// to the next version that is pending activation.
func shouldPropagateToNextVersion(body *protocol.Body) bool {
	switch {
	case body.RuntimeConsensusSyncRequest != nil:
		// Consensus view of the next version should be up to date as otherwise signed attestations
		// will be stale, resulting in them being rejected by the consensus layer.
		return true
	case body.RuntimeKeyManagerStatusUpdateRequest != nil,
		body.RuntimeKeyManagerQuotePolicyUpdateRequest != nil:
		// Key manager updates should be propagated so that the runtime is ready when activated.
		return true
	default:
		return false
	}
}

// Call implements host.Runtime.
func (agg *Aggregate) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	var (
		activeHost host.Runtime
		nextHost   host.Runtime
	)
	getHostsFn := func() error {
		agg.l.RLock()
		defer agg.l.RUnlock()

		if agg.active == nil {
			return ErrNoActiveVersion
		}
		activeHost = agg.active.host

		if agg.next != nil {
			nextHost = agg.next.host
		}

		return nil
	}
	// Retry call in case the runtime is not yet ready.
	err := backoff.Retry(getHostsFn, backoff.WithContext(cmnBackoff.NewExponentialBackOff(), ctx))
	if err != nil {
		return nil, err
	}

	// Take care to release lock before calling into the runtime as otherwise this could lead to a
	// deadlock in case the runtime makes a call that acquires the cross node lock and at the same
	// time SetVersion is being called to update the version with the cross node lock acquired.

	// Check if request should be propagated to the next version.
	if nextHost != nil && shouldPropagateToNextVersion(body) {
		_, err = nextHost.Call(ctx, body)
		if err != nil {
			agg.logger.Warn("failed to propagate runtime request to next version",
				"err", err,
			)
		}
	}

	return activeHost.Call(ctx, body)
}

// UpdateCapabilityTEE implements host.Runtime.
func (agg *Aggregate) UpdateCapabilityTEE() {
	agg.l.RLock()
	defer agg.l.RUnlock()

	if agg.active != nil {
		agg.active.host.UpdateCapabilityTEE()
	}
	if agg.next != nil {
		agg.next.host.UpdateCapabilityTEE()
	}
}

// WatchEvents implements host.Runtime.
func (agg *Aggregate) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	typedCh := make(chan *host.Event)
	sub := agg.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub
}

// Start implements host.Runtime.
func (agg *Aggregate) Start() {
	agg.l.RLock()
	defer agg.l.RUnlock()

	// This is "ok", sort of, though maybe this should fail.
	if agg.active == nil {
		return
	}

	agg.active.host.Start()
}

// Abort implements host.Runtime.
func (agg *Aggregate) Abort(ctx context.Context, force bool) error {
	active, err := agg.getActiveHost()
	if err != nil {
		return err
	}
	return active.host.Abort(ctx, force)
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

// Component implements host.CompositeRuntime.
func (agg *Aggregate) Component(id component.ID) (host.Runtime, bool) {
	active, err := agg.getActiveHost()
	if err != nil {
		return nil, false
	}

	if cr, ok := active.host.(host.CompositeRuntime); ok {
		return cr.Component(id)
	}
	if id.IsRONL() {
		return active.host, true
	}
	return nil, false
}

// GetVersion retrieves the runtime host for the specified version.
func (agg *Aggregate) GetVersion(version version.Version) (host.Runtime, error) {
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

// AddVersion adds a new runtime version to the aggregate.
//
// The provided runtime must be newly provisioned, meaning Start() has not been
// called yet.
func (agg *Aggregate) AddVersion(rt host.Runtime, version version.Version) error {
	agg.l.Lock()
	defer agg.l.Unlock()

	if id := rt.ID(); id != agg.id {
		return fmt.Errorf("runtime/host/multi: runtime mismatch: got '%s', expected '%s'", id, agg.id)
	}

	if _, ok := agg.hosts[version]; ok {
		return fmt.Errorf("runtime/host/multi: duplicate runtime version: %v", version)
	}

	agg.hosts[version] = newAggregateHost(rt, version)

	return nil
}

// SetVersion sets the active and next runtime versions.  This routine will:
//   - Do nothing if the active version is already the requested version.
//   - Unconditionally tear down the currently active version (via Stop()).
//   - Start the newly active version if it exists.
//   - Do nothing if the next version is already the requested version.
//   - Start the next version if it exists.
func (agg *Aggregate) SetVersion(active version.Version, next *version.Version) error {
	agg.l.Lock()
	defer agg.l.Unlock()

	agg.logger.Info("set version",
		"active", active,
		"next", next,
	)

	if err := agg.setActiveVersionLocked(active); err != nil {
		return err
	}
	return agg.setNextVersionLocked(next)
}

func (agg *Aggregate) setActiveVersionLocked(version version.Version) error {
	// Contract: agg.l already locked for write.

	next := agg.hosts[version]

	// Ensure that we know about the new version.
	if next == nil {
		agg.logger.Error("SetVersion: unknown version",
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
		host.Start()
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
			"version", agg.active.version,
		)
		break
	}

	// Close off the subscription, invalidate the old sub-host.
	agg.active.sub.Close()
	agg.hosts[agg.active.version] = nil
	agg.active = nil
}

func (agg *Aggregate) setNextVersionLocked(maybeVersion *version.Version) error {
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
			"version", version,
			"previous_version", agg.next.version,
		)
		agg.stopNextLocked()
	}

	// Start the next version.
	next.host.Start()

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
