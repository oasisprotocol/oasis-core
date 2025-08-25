// Package sandbox implements the runtime provisioner for runtimes in sandboxed processes.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/sandbox/process"
)

var errRuntimeNotReady = errors.New("runtime is not yet ready")

const (
	runtimeInitTimeout         = 1 * time.Second
	runtimeExtendedInitTimeout = 120 * time.Second
	runtimeInterruptTimeout    = 1 * time.Second
	stopTickerTimeout          = 15 * time.Minute
	watchdogInterval           = 15 * time.Second
	watchdogPingTimeout        = 5 * time.Second

	ctrlChannelBufferSize = 16
)

// HostInitializerParams contains parameters for the HostInitializer function.
type HostInitializerParams struct {
	Runtime    host.Runtime
	Config     *host.Config
	Version    version.Version
	Process    process.Process
	Connection protocol.Connection

	NotifyUpdateCapabilityTEE <-chan struct{}
}

// abortRequest is a request to the runtime manager goroutine to abort the runtime.
// In case of failures or if force flag is set, the runtime is restarted.
type abortRequest struct {
	ch    chan<- error
	force bool
}

type sandboxHost struct {
	sync.RWMutex

	cfg   Config
	rtCfg host.Config
	id    common.Namespace

	startOne cmSync.One
	ctrlCh   chan any

	process  process.Process
	conn     protocol.Connection
	notifier *pubsub.Broker

	notifyUpdateCapabilityTEECh chan struct{}
	capabilityTEE               *node.CapabilityTEE

	rtVersion *version.Version

	logger *logging.Logger
}

// Implements host.Runtime.
func (h *sandboxHost) ID() common.Namespace {
	return h.id
}

// GetActiveVersion implements host.Runtime.
func (h *sandboxHost) GetActiveVersion() (*version.Version, error) {
	h.RLock()
	defer h.RUnlock()

	if h.conn == nil {
		return nil, errRuntimeNotReady
	}
	return h.rtVersion, nil
}

// Implements host.Runtime.
func (h *sandboxHost) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	conn, err := h.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	return conn.GetInfo()
}

// Implements host.Runtime.
func (h *sandboxHost) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	h.RLock()
	defer h.RUnlock()

	if h.conn == nil {
		return nil, errRuntimeNotReady
	}
	return h.capabilityTEE, nil
}

// Implements host.Runtime.
func (h *sandboxHost) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	conn, err := h.getConnection(ctx)
	if err != nil {
		return nil, err
	}

	// Take care to release lock before calling into the runtime as otherwise this could lead to a
	// deadlock in case the runtime makes a call that acquires the cross node lock and at the same
	// time SetVersion is being called to update the version with the cross node lock acquired.

	return conn.Call(ctx, body)
}

func (h *sandboxHost) getConnection(ctx context.Context) (protocol.Connection, error) {
	var conn protocol.Connection
	getConnFn := func() error {
		h.RLock()
		defer h.RUnlock()

		if h.conn == nil {
			return errRuntimeNotReady
		}
		conn = h.conn

		return nil
	}
	// Retry call in case the runtime is not yet ready.
	err := backoff.Retry(getConnFn, backoff.WithContext(cmnBackoff.NewExponentialBackOff(), ctx))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Implements host.Runtime.
func (h *sandboxHost) UpdateCapabilityTEE() {
	select {
	case h.notifyUpdateCapabilityTEECh <- struct{}{}:
	default:
	}
}

// Implements host.Runtime.
func (h *sandboxHost) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	ch := make(chan *host.Event)
	sub := h.notifier.Subscribe()
	sub.Unwrap(ch)

	return ch, sub
}

// Implements host.Runtime.
func (h *sandboxHost) Start() {
	h.startOne.TryStart(h.manager)
}

// Implements host.Runtime.
func (h *sandboxHost) Abort(ctx context.Context, force bool) error {
	// Ignore abort requests when connection is not available.
	h.RLock()
	if h.conn == nil {
		h.RUnlock()
		return nil
	}
	h.RUnlock()

	// Send internal request to the manager goroutine.
	ch := make(chan error, 1)
	select {
	case h.ctrlCh <- &abortRequest{ch: ch, force: force}:
	default:
		// If the command channel is full, do not queue more abort requests.
		return fmt.Errorf("command channel is full")
	}

	// Wait for response from the manager goroutine.
	select {
	case err := <-ch:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Implements host.Runtime.
func (h *sandboxHost) Stop() {
	h.startOne.TryStop()
}

// Implements host.EmitEvent.
func (h *sandboxHost) EmitEvent(ev *host.Event) {
	h.notifier.Broadcast(ev)
}

func (h *sandboxHost) startProcess(ctx context.Context) (err error) {
	// Create a temporary directory.
	runtimeDir, err := os.MkdirTemp("", "oasis-runtime")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	// We can remove the worker directory after the worker has been started as it
	// has been mounted into the sandbox and is no longer needed.
	defer os.RemoveAll(runtimeDir)

	// Create a new connector.
	connector, err := h.cfg.Connector(h.logger, runtimeDir, !h.cfg.InsecureNoSandbox)
	if err != nil {
		return err
	}
	defer connector.Close()

	// Create the sandbox as configured.
	var p process.Process
	var ok bool
	defer func() {
		// Make sure the process gets killed in case of errors.
		if !ok && p != nil {
			p.Kill()
		}
	}()

	cfg, err := h.cfg.GetSandboxConfig(h.rtCfg, connector, runtimeDir)
	if err != nil {
		return fmt.Errorf("failed to configure process: %w", err)
	}
	if err = connector.Configure(&h.rtCfg, &cfg); err != nil {
		return err
	}

	switch h.cfg.InsecureNoSandbox {
	case true:
		// No sandbox.
		h.logger.Warn("starting an UNSANDBOXED runtime")

		p, err = process.NewNaked(cfg)
		if err != nil {
			return fmt.Errorf("failed to spawn process: %w", err)
		}
	case false:
		// With sandbox.
		p, err = process.NewBubbleWrap(cfg)
		if err != nil {
			return fmt.Errorf("failed to spawn sandbox: %w", err)
		}
	}

	// Wait for the runtime to connect.
	h.logger.Info("waiting for runtime to connect",
		"pid", p.GetPID(),
	)

	conn, err := connector.Connect(p)
	if err != nil {
		return err
	}

	// Initialize the connection.
	h.logger.Info("runtime connected",
		"pid", p.GetPID(),
	)

	pc, err := protocol.NewConnection(h.logger, h.id, h.rtCfg.MessageHandler, h.cfg.MetricsEnabled)
	if err != nil {
		return fmt.Errorf("failed to create connection: %w", err)
	}
	defer func() {
		// Make sure the connection gets cleaned up in case of errors.
		if !ok {
			pc.Close()
		}
	}()

	// Populate the runtime-specific parts of host information.
	hi := h.cfg.HostInfo.Clone()
	hi.LocalConfig = h.rtCfg.LocalConfig

	// Perform common host initialization.
	initCtx, cancelInit := context.WithTimeout(ctx, runtimeInitTimeout)
	defer cancelInit()

	rtVersion, err := pc.InitHost(initCtx, conn, hi)
	if err != nil {
		return fmt.Errorf("failed to initialize connection: %w", err)
	}

	if comp := h.rtCfg.Component; comp.ID().IsRONL() {
		// Make sure the version matches what is configured in the bundle. This check is skipped for
		// non-RONL components to support detached bundles.
		if bndVersion := comp.Version; *rtVersion != bndVersion {
			return fmt.Errorf("version mismatch (runtime reported: %s bundle: %s)", *rtVersion, bndVersion)
		}
	}

	hp := &HostInitializerParams{
		Runtime:                   h,
		Config:                    &h.rtCfg,
		Version:                   *rtVersion,
		Process:                   p,
		Connection:                pc,
		NotifyUpdateCapabilityTEE: h.notifyUpdateCapabilityTEECh,
	}

	// Perform configuration-specific host initialization.
	exInitCtx, cancelExInit := context.WithTimeout(ctx, runtimeExtendedInitTimeout)
	defer cancelExInit()

	ev, err := h.cfg.HostInitializer(exInitCtx, hp)
	if err != nil {
		return fmt.Errorf("failed to initialize connection: %w", err)
	}

	ok = true
	h.process = p
	h.Lock()
	h.conn = pc
	h.capabilityTEE = ev.CapabilityTEE
	h.rtVersion = rtVersion
	h.Unlock()

	// Ensure the command queue is empty to avoid processing any stale requests after the
	// runtime restarts.
drainLoop:
	for {
		select {
		case grq := <-h.ctrlCh:
			switch rq := grq.(type) {
			case *abortRequest:
				rq.ch <- fmt.Errorf("runtime restarted")
				close(rq.ch)
			default:
				// Ignore unknown requests.
			}
		default:
			break drainLoop
		}
	}

	// Notify subscribers that a runtime has been started.
	h.notifier.Broadcast(&host.Event{Started: ev})

	return nil
}

func (h *sandboxHost) handleAbortRequest(ctx context.Context, rq *abortRequest) error {
	h.logger.Warn("interrupting runtime")

	// First attempt to gracefully interrupt the runtime by sending a request.
	callCtx, cancelCall := context.WithTimeout(ctx, runtimeInterruptTimeout)
	defer cancelCall()

	response, err := h.conn.Call(callCtx, &protocol.Body{RuntimeAbortRequest: &protocol.Empty{}})
	if err == nil && response.RuntimeAbortResponse != nil && !rq.force {
		// Successful response, and no force restart required.
		return nil
	}

	h.logger.Warn("restarting runtime", "force_restart", rq.force, "abort_err", err, "abort_resp", response)

	// Failed to gracefully interrupt the runtime. Kill the runtime and it will be automatically
	// restarted by the manager after it dies.
	h.process.Kill()

	// Wait for the runtime to terminate. We do this here so that the response to the interrupt
	// request is only sent after the new runtime has been respawned and is ready to use.
	select {
	case <-h.process.Wait():
	case <-ctx.Done():
		return ctx.Err()
	}

	h.logger.Warn("runtime terminated due to restart request")

	// Remove the process so it will be respanwed (it would be respawned either way, but with an
	// additional "unexpected termination" message).
	h.conn.Close()
	h.process = nil
	h.Lock()
	h.conn = nil
	h.capabilityTEE = nil
	h.rtVersion = nil
	h.Unlock()

	// Notify subscribers that the runtime has stopped.
	h.notifier.Broadcast(&host.Event{Stopped: &host.StoppedEvent{}})

	return nil
}

// watchdogPing pings the runtime for liveness and terminates the process in case response is not
// received in time.
func (h *sandboxHost) watchdogPing(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, watchdogPingTimeout)
	defer cancel()

	// Send a single ping request and expect a response.
	_, err := h.conn.Call(ctx, &protocol.Body{RuntimePingRequest: &protocol.Empty{}})
	if err == nil {
		return // If there is no error, we stop here.
	}

	h.logger.Warn("watchdog ping failed, terminating runtime", "err", err)

	// Kill the process and trigger a runtime restart.
	h.process.Kill()
}

func (h *sandboxHost) manager(ctx context.Context) {
	var ticker *backoff.Ticker

	defer func() {
		h.logger.Warn("terminating runtime")

		if ticker != nil {
			ticker.Stop()
			ticker = nil
		}
		if h.process != nil {
			h.conn.Close()
			h.process.Kill()
			<-h.process.Wait()
			h.process = nil

			h.Lock()
			h.conn = nil
			h.capabilityTEE = nil
			h.Unlock()
		}

		// Notify subscribers that the runtime has stopped.
		h.notifier.Broadcast(&host.Event{Stopped: &host.StoppedEvent{}})

		h.cfg.Cleanup(h.rtCfg)
	}()

	// Subscribe to own events to make sure the cached CapabilityTEE remains up-to-date.
	evCh, evSub := h.WatchEvents()
	defer evSub.Close()

	var (
		attempt      int
		stopTickerCh <-chan time.Time
		watchdogCh   <-chan time.Time
	)
	for {
		// Terminate immediately when requested.
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Make sure to restart the process if terminated.
		if h.process == nil {
			firstTickCh := make(chan struct{}, 1)
			if ticker == nil {
				// Initialize a ticker for restarting the process. We use a separate channel
				// to restart the process immediately on the first run, as we don't want to wait
				// for the first tick.
				ticker = backoff.NewTicker(cmnBackoff.NewExponentialBackOff())
				firstTickCh <- struct{}{}
				attempt = 0
			}

			select {
			case <-ctx.Done():
				h.logger.Warn("termination requested")
				return
			case <-firstTickCh:
			case <-ticker.C:
			}

			attempt++
			h.logger.Info("starting runtime",
				"attempt", attempt,
			)

			if err := h.startProcess(ctx); err != nil {
				h.logger.Error("failed to start runtime",
					"err", err,
				)

				// Notify subscribers that a runtime has failed to start.
				h.notifier.Broadcast(&host.Event{
					FailedToStart: &host.FailedToStartEvent{
						Error: err,
					},
				})

				continue
			}

			// After the process has been (re)started, set up fresh tickers.
			stopTickerCh = time.After(stopTickerTimeout)
			watchdogCh = time.Tick(watchdogInterval)
		}

		// Wait for either the runtime or the runtime manager to terminate.
		select {
		case grq := <-h.ctrlCh:
			switch rq := grq.(type) {
			case *abortRequest:
				// Request to abort the runtime.
				rq.ch <- h.handleAbortRequest(ctx, rq)
				close(rq.ch)
			default:
				h.logger.Error("received unknown request type",
					"request_type", fmt.Sprintf("%T", rq),
				)
			}
		case <-ctx.Done():
			h.logger.Warn("termination requested")
			return
		case <-h.process.Wait():
			// Process has terminated.
			h.logger.Error("runtime process has terminated unexpectedly",
				"err", h.process.Error(),
			)

			h.conn.Close()
			h.process = nil
			h.Lock()
			h.conn = nil
			h.capabilityTEE = nil
			h.rtVersion = nil
			h.Unlock()

			// Notify subscribers that the runtime has stopped.
			h.notifier.Broadcast(&host.Event{Stopped: &host.StoppedEvent{}})
		case <-stopTickerCh:
			// Stop the ticker if things work smoothly. Otherwise, keep on using the old ticker as
			// it can happen that the runtime constantly terminates after a successful start.
			if ticker != nil {
				ticker.Stop()
				ticker = nil
			}
		case ev := <-evCh:
			// Update runtime's CapabilityTEE in case this is an update event.
			if ue := ev.Updated; ue != nil {
				h.Lock()
				h.capabilityTEE = ue.CapabilityTEE
				h.Unlock()
			}
		case <-watchdogCh:
			// Check for runtime liveness.
			h.watchdogPing(ctx)
		}
	}
}
