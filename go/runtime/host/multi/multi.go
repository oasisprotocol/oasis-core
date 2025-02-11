// Package multi implements support for a runtime host aggregator that
// handles multiplexing multiple instances of other runtime hosts, to
// enable seamless transitions between versions.
package multi

import (
	"context"
	"errors"
	"fmt"
	"slices"
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

func (ah *aggregatedHost) stopDiscard(notifier *pubsub.Broker) {
	close(ah.stopDiscardCh)
	ev := <-ah.stoppedDiscardCh

	// Propagate captured started event.
	if ev != nil && notifier != nil {
		notifier.Broadcast(ev)
	}
}

func (ah *aggregatedHost) startPassthrough(notifier *pubsub.Broker) {
	go func() {
		defer close(ah.stoppedCh)
		for {
			select {
			case <-ah.stopCh:
				return
			case ev := <-ah.ch:
				notifier.Broadcast(ev)
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

	running bool
	hosts   map[version.Version]*aggregatedHost

	active        *aggregatedHost
	activeVersion *version.Version

	next        *aggregatedHost
	nextVersion *version.Version

	notifier *pubsub.Broker

	logger *logging.Logger
}

// New returns a new aggregated runtime.
func New(id common.Namespace) *Aggregate {
	logger := logging.GetLogger("runtime/host/multi").With("runtime_id", id)

	return &Aggregate{
		id:            id,
		running:       false,
		hosts:         make(map[version.Version]*aggregatedHost),
		active:        nil,
		activeVersion: nil,
		next:          nil,
		nextVersion:   nil,
		notifier:      pubsub.NewBroker(false),
		logger:        logger,
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
	agg.l.Lock()
	defer agg.l.Unlock()

	if agg.running {
		return
	}
	agg.running = true

	agg.logger.Info("starting aggregate")

	agg.startActiveLocked()
	agg.startNextLocked()
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

	if !agg.running {
		return
	}
	agg.running = false

	agg.logger.Info("stopping aggregate")

	agg.stopActiveLocked()
	agg.stopNextLocked()

	// This is only used for teardown, so while not great, it is ok that
	// this leaves the notifier lying around.
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

// Versions returns a sorted list of all versions in the aggregate.
func (agg *Aggregate) Versions() []version.Version {
	agg.l.RLock()
	defer agg.l.RUnlock()

	versions := make([]version.Version, 0, len(agg.hosts))
	for v := range agg.hosts {
		versions = append(versions, v)
	}

	slices.SortFunc(versions, version.Version.Cmp)
	return versions
}

// Version retrieves the runtime host for the specified version.
func (agg *Aggregate) Version(version version.Version) (host.Runtime, error) {
	agg.l.RLock()
	defer agg.l.RUnlock()

	host, ok := agg.hosts[version]
	if !ok {
		return nil, ErrNoSuchVersion
	}
	// Only allow fetching either the active or next versions.
	if host != agg.active && host != agg.next {
		return nil, ErrNoSuchVersion
	}
	return host.host, nil
}

// HasVersion checks if runtime host exists for the specified version.
func (agg *Aggregate) HasVersion(version version.Version) bool {
	agg.l.RLock()
	defer agg.l.RUnlock()

	_, ok := agg.hosts[version]
	return ok
}

// AddVersion adds a new runtime version to the aggregate.
//
// If the newly added version matches the active or the next version,
// this function will start the provided runtime.
//
// The provided runtime must be newly provisioned, meaning Start() has not been
// called yet.
func (agg *Aggregate) AddVersion(version version.Version, rt host.Runtime) error {
	agg.l.Lock()
	defer agg.l.Unlock()

	agg.logger.Info("adding version", "version", version)

	if id := rt.ID(); id != agg.id {
		return fmt.Errorf("runtime/host/multi: runtime mismatch: got '%s', expected '%s'", id, agg.id)
	}

	if _, ok := agg.hosts[version]; ok {
		return fmt.Errorf("runtime/host/multi: duplicate runtime version: %v", version)
	}

	agg.hosts[version] = newAggregateHost(rt, version)

	agg.logger.Info("version added", "version", version)

	if agg.running {
		agg.startActiveLocked()
		agg.startNextLocked()
	}

	return nil
}

// RemoveVersion removes the specified version from the aggregate.
//
// A version cannot be removed if it is currently running, meaning it
// is marked as the active version or the next version.
func (agg *Aggregate) RemoveVersion(version version.Version) error {
	agg.l.Lock()
	defer agg.l.Unlock()

	agg.logger.Info("removing version", "version", version)

	if _, ok := agg.hosts[version]; !ok {
		return ErrNoSuchVersion
	}
	if agg.activeVersion != nil && version == *agg.activeVersion {
		return fmt.Errorf("runtime/host/multi: cannot remove active version '%s'", version)
	}
	if agg.nextVersion != nil && version == *agg.nextVersion {
		return fmt.Errorf("runtime/host/multi: cannot remove next version '%s'", version)
	}
	delete(agg.hosts, version)

	agg.logger.Info("version removed", "version", version)

	return nil
}

// SetVersion updates the active and next runtime versions.
//
// If the aggregate is not running, this function simply updates the versions.
// Otherwise, it performs the following steps:
//   - If the active version differs from the requested active version, it is
//     unconditionally torn down using Stop().
//   - If the requested active version has already been started as next version,
//     the next version becomes the new active session. Otherwise, the new active
//     version is started if it exists.
//   - If the next version differs from the requested next version, it is
//     unconditionally torn down using Stop().
//   - If the next version is already the requested version, no action is taken.
//     Otherwise, the new next version is started if it exists.
func (agg *Aggregate) SetVersion(active *version.Version, next *version.Version) {
	agg.l.Lock()
	defer agg.l.Unlock()

	agg.logger.Info("set version",
		"active", active,
		"next", next,
	)

	agg.activeVersion = active
	agg.nextVersion = next

	switch {
	case agg.activeVersion == agg.nextVersion:
		// Ensure the next version is not the same as the active version.
		agg.nextVersion = nil
	case agg.activeVersion == nil && agg.nextVersion != nil:
		// Ensure the active version is set first.
		agg.activeVersion = agg.nextVersion
		agg.nextVersion = nil
	}

	if !agg.running {
		return
	}

	agg.startActiveLocked()
	agg.startNextLocked()
}

func (agg *Aggregate) startActiveLocked() {
	// Contract: agg.l already locked for write.

	// If the active version is already running, no action is needed.
	if agg.active != nil && agg.activeVersion != nil && agg.active.version == *agg.activeVersion {
		return
	}

	// Tear down the active version, if any.
	agg.stopActiveLocked()

	// If there's no new active version to start, exit.
	if agg.activeVersion == nil {
		return
	}
	version := *agg.activeVersion

	// Use the next version if it matches and has been started in advance.
	if agg.next != nil && agg.next.version == version {
		agg.logger.Debug("changing next version to active",
			"version", version,
		)

		// Promote next to active.
		agg.active = agg.next
		agg.next = nil

		// Stop discarding events and forward any captured started events.
		agg.active.stopDiscard(agg.notifier)

		// Start event propagation.
		agg.active.startPassthrough(agg.notifier)

		return
	}

	// If the new active version is unknown, postpone startup.
	active, ok := agg.hosts[version]
	if !ok {
		agg.logger.Warn("unknown active version, postponing startup",
			"version", version,
		)
		return
	}
	agg.active = active

	// Spin up the new active version.
	agg.logger.Debug("starting active version",
		"version", version,
	)
	agg.active.host.Start()

	// Start event propagation.
	agg.active.startPassthrough(agg.notifier)
}

func (agg *Aggregate) stopActiveLocked() {
	// Contract: agg.l already locked for write.

	if agg.active == nil {
		return
	}

	agg.logger.Debug("stopping active version",
		"version", agg.active.version,
	)

	// Remove the runtime's event channel from the pubsub aggregator
	// before halting the previous active version so that we can catch
	// the host.StoppedEvent and not propagate it if requested to
	// do so.
	agg.active.stopPassthrough()

	// Terminate the active instance.
	agg.active.host.Stop()

	// Wait for a host.StoppedEvent, while passing events through to the
	// aggregator.
	for {
		ev := <-agg.active.ch
		agg.notifier.Broadcast(ev) // Propagate
		if ev.Stopped == nil {
			continue
		}
		agg.logger.Debug("stopped old sub-host",
			"version", agg.active.version,
		)
		break
	}

	// Close off the subscription, invalidate the old sub-host.
	agg.active.sub.Close()
	delete(agg.hosts, agg.active.version)
	agg.active = nil
}

func (agg *Aggregate) startNextLocked() {
	// Contract: agg.l already locked for write.

	// If the next version is already running, no action is needed.
	if agg.next != nil && agg.nextVersion != nil && agg.next.version == *agg.nextVersion {
		return
	}

	// Tear down the next version, if any. The next version could become
	// unscheduled,
	agg.stopNextLocked()

	// If there's no new next version to start, exit.
	if agg.nextVersion == nil {
		return
	}
	version := *agg.nextVersion

	// If the new next version is unknown, postpone startup.
	next, ok := agg.hosts[version]
	if !ok {
		agg.logger.Warn("unknown next version, postponing startup",
			"version", version,
		)
		return
	}
	agg.next = next

	// Spin up the new next version.
	agg.logger.Debug("starting next version",
		"version", version,
	)
	agg.next.host.Start()

	// Start discarding events.
	agg.next.startDiscard()

	// Notify subscribers that configuration has changed.
	agg.notifier.Broadcast(&host.Event{ConfigUpdated: &host.ConfigUpdatedEvent{}})
}

func (agg *Aggregate) stopNextLocked() {
	// Contract: agg.l already locked for write.

	if agg.next == nil {
		return
	}

	agg.logger.Debug("stopping next version",
		"version", agg.next.version,
	)

	// Warn in case the next version is changed but the previous one was not
	// activated yet.
	if agg.nextVersion != nil {
		agg.logger.Warn("overwriting next version without activation",
			"version", agg.nextVersion,
			"previous_version", agg.next.version,
		)
	}

	agg.next.stopDiscard(nil) // Drop any captured started events.

	// Terminate the next instance.
	agg.next.host.Stop()

	// Close off the subscription, invalidate the old sub-host.
	agg.next.sub.Close()
	delete(agg.hosts, agg.next.version)
	agg.next = nil

	// Notify subscribers that configuration has changed.
	agg.notifier.Broadcast(&host.Event{ConfigUpdated: &host.ConfigUpdatedEvent{}})
}
