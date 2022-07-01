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

	ch        <-chan *host.Event
	sub       pubsub.ClosableSubscription
	stopCh    chan struct{}
	stoppedCh chan struct{}

	version version.Version
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
}

// SetVersion sets the active runtime version.  This routine will:
//  - Do nothing if the active version is already the requested version.
//  - Unconditionally tear down the currently active version (via Stop()).
//  - Start the newly active version if it exists.
func (agg *Aggregate) SetVersion(ctx context.Context, version version.Version) error {
	agg.l.Lock()
	defer agg.l.Unlock()

	agg.logger.Info("SetVersion",
		"id", agg.ID(),
		"version", version,
	)

	// Ensure that we know about the new version.
	if agg.hosts[version] == nil {
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
		if agg.hosts[version] == agg.active {
			return nil
		}

		// Otherwise tear it dow.
		agg.stopActiveLocked()
	}

	// Get ready to spin up the new runtime.
	var err error
	ah := agg.hosts[version]

	host := ah.host
	if err = host.Start(); err != nil {
		// Do not bail, this can't actually fail in practice because
		// the part that does all the work is async.  Log something.
		agg.logger.Error("SetVersion: failed to start sub-host",
			"err", err,
			"id", agg.ID(),
			"version", version,
		)
	}

	// Assume that the caller is ok with SetVersion acting as a Stop+Start
	// and just start propagating events immediately.
	ah.startPassthrough(agg)

	// Active runtime swapped out, update the state and return.
	agg.active = ah

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
			host:      rts[version],
			ch:        ch,
			sub:       sub,
			stopCh:    make(chan struct{}),
			stoppedCh: make(chan struct{}),
			version:   version,
		}
		agg.hosts[version] = ah
	}

	return agg, nil
}
