package registration

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/prometheus/client_golang/prometheus"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	sentryClient "github.com/oasisprotocol/oasis-core/go/sentry/client"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
)

const (
	// DBBucketName is the name of the database bucket for the registration
	// worker's service store.
	DBBucketName = "worker/registration"

	periodicMetricsInterval = 60 * time.Second
)

var (
	deregistrationRequestStoreKey = []byte("deregistration requested")

	allowUnroutableAddresses bool

	workerNodeRegistered = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_worker_node_registered",
			Help: "Is oasis node registered (binary).",
		},
	)
	workerNodeStatusFrozen = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_worker_node_status_frozen",
			Help: "Is oasis node frozen (binary).",
		},
	)
	workerNodeRegistrationEligible = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_worker_node_registration_eligible",
			Help: "Is oasis node eligible for registration (binary).",
		},
	)
	workerNodeStatusFaults = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_node_status_runtime_faults",
			Help: "Number of runtime faults.",
		},
		[]string{"runtime"},
	)
	workerNodeRuntimeSuspended = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_node_status_runtime_suspended",
			Help: "Runtime node suspension status (binary).",
		},
		[]string{"runtime"},
	)

	nodeCollectors = []prometheus.Collector{
		workerNodeRegistered,
		workerNodeStatusFrozen,
		workerNodeRegistrationEligible,
		workerNodeStatusFaults,
		workerNodeRuntimeSuspended,
	}

	metricsOnce sync.Once
)

// RegisterNodeHook is a function that is used to update the node descriptor.
type RegisterNodeHook func(*node.Node) error

// RegisterNodeCallback is a function that is called after a successful registration.
type RegisterNodeCallback func(context.Context) error

// Delegate is the interface for objects that wish to know about the worker's events.
type Delegate interface {
	// RegistrationStopped is called by the worker when the registration loop exits cleanly.
	RegistrationStopped()
}

// RoleProvider is the node descriptor role provider interface.
//
// It is used to reserve a slot in the node descriptor that will be filled when the role provider
// decides that it is available. This is used so that the registration worker knows when certain
// roles are ready to be serviced by the node.
//
// An unavailable role provider will prevent the node from being (re-)registered.
type RoleProvider interface {
	// IsAvailable returns true if the role provider is available.
	IsAvailable() bool

	// SetAvailable signals that the role provider is available and that node registration can
	// thus proceed.
	SetAvailable(hook RegisterNodeHook)

	// SetAvailableWithCallback signals that the role provider is available and that node
	// registration can thus proceed.
	//
	// If the passed cb is non-nil, it will be called once after the next successful registration
	// that includes the node descriptor updated by the passed hook.
	SetAvailableWithCallback(hook RegisterNodeHook, cb RegisterNodeCallback)

	// SetUnavailable signals that the role provider is unavailable and that node registration
	// should be blocked until the role provider becomes available.
	SetUnavailable()
}

type roleProvider struct {
	sync.Mutex

	w *Worker

	version   uint64
	role      node.RolesMask
	runtimeID *common.Namespace
	hook      RegisterNodeHook
	cb        RegisterNodeCallback
}

func (rp *roleProvider) IsAvailable() bool {
	rp.Lock()
	available := (rp.hook != nil)
	rp.Unlock()
	return available
}

func (rp *roleProvider) SetAvailable(hook RegisterNodeHook) {
	rp.SetAvailableWithCallback(hook, nil)
}

func (rp *roleProvider) SetAvailableWithCallback(hook RegisterNodeHook, cb RegisterNodeCallback) {
	rp.Lock()
	rp.version++
	rp.hook = hook
	rp.cb = cb
	rp.Unlock()

	// Notify worker that role provider has been updated.
	select {
	case rp.w.registerCh <- struct{}{}:
	default:
	}
}

func (rp *roleProvider) SetUnavailable() {
	rp.SetAvailable(nil)
}

// Worker is a service handling worker node registration.
type Worker struct { // nolint: maligned
	sync.RWMutex

	workerCommonCfg *workerCommon.Config

	store            *persistent.ServiceStore
	storedDeregister bool
	deregRequested   uint32
	delegate         Delegate

	entityID           signature.PublicKey
	registrationSigner signature.Signer

	sentryAddresses []node.TLSAddress

	runtimeRegistry runtimeRegistry.Registry
	beacon          beacon.Backend
	registry        registry.Backend
	identity        *identity.Identity
	p2p             p2p.Service
	ctx             context.Context

	// Bandaid: Idempotent Stop for testing.
	stopped      uint32
	stopCh       chan struct{} // closed internally to trigger stop
	quitCh       chan struct{} // closed after stopped
	initialRegCh chan struct{} // closed after initial registration
	stopRegCh    chan struct{} // closed internally to trigger clean registration lapse

	logger    *logging.Logger
	consensus consensus.Service

	roleProviders []*roleProvider
	registerCh    chan struct{}

	status control.RegistrationStatus
}

// DebugForceAllowUnroutableAddresses allows unroutable addresses.
func DebugForceAllowUnroutableAddresses() {
	allowUnroutableAddresses = true
}

func (w *Worker) registrationLoop() { // nolint: gocyclo
	// Delay node registration till after the consensus service has
	// finished initial synchronization if applicable.
	var (
		blockCh <-chan *consensus.Block

		delayReregistration    bool
		maxReregistrationDelay int64
	)
	if w.consensus != nil {
		w.logger.Debug("waiting for consensus sync")
		select {
		case <-w.stopCh:
			return
		case <-w.stopRegCh:
			return
		case <-w.consensus.Synced():
		}
		w.logger.Debug("consensus synced, entering registration loop")

		beaconParameters, err := w.beacon.ConsensusParameters(w.ctx, consensus.HeightLatest)
		switch err {
		case nil:
			delayReregistration = beaconParameters.Backend == beacon.BackendVRF
			if delayReregistration {
				epochInterval := beaconParameters.VRFParameters.Interval
				maxReregistrationDelay = epochInterval / 100 * 5 // 5%
				if maxReregistrationDelay == 0 {
					w.logger.Warn("epoch interval too short to provide meaningful re-registration delay",
						"epoch_interval", epochInterval,
					)
					delayReregistration = false
				}
			}
		default:
			w.logger.Error("failed to query beacon parameters",
				"err", err,
			)
		}

	}
	if delayReregistration {
		// Register for block heights so we can impose a random re-registration
		// delay if needed.
		var (
			blockSub pubsub.ClosableSubscription
			err      error
		)
		blockCh, blockSub, err = w.consensus.Core().WatchBlocks(w.ctx)
		switch err {
		case nil:
			defer blockSub.Close()
		default:
			w.logger.Error("failed to watch blocks",
				"err", err,
			)
		}
	}

	// (re-)register the node on each epoch transition. This doesn't
	// need to be strict block-epoch time, since it just serves to
	// extend the node's expiration, and we add a randomized delay
	// anyway.
	ch, sub, err := w.beacon.WatchLatestEpoch(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer sub.Close()

	regFn := func(epoch beacon.EpochTime, hook RegisterNodeHook, retry bool) error {
		var off backoff.BackOff

		switch retry {
		case true:
			off = cmnBackoff.NewExponentialBackOff()
		case false:
			off = &backoff.StopBackOff{}
		}
		off = backoff.WithContext(off, w.ctx)

		// WARNING: This can potentially infinite loop, on certain
		// "shouldn't be possible" pathological failures.
		//
		// w.ctx being canceled will break out of the loop correctly
		// but it's entirely possible to sit around in an infinite
		// retry loop with no hope of success.
		return backoff.Retry(func() error {
			// Update the epoch if it happens to change while retrying.
			var ok bool
			select {
			case <-w.stopCh:
				return backoff.Permanent(context.Canceled)
			case <-w.stopRegCh:
				return backoff.Permanent(context.Canceled)
			case epoch, ok = <-ch:
				if !ok {
					return context.Canceled
				}
			default:
			}

			err := w.registerNode(epoch, hook)
			switch err {
			case nil:
				workerNodeRegistered.Set(1.0)
			default:
				workerNodeRegistered.Set(0.0)
			}
			return err
		}, off)
	}

	// (re-)register the node on entity registration update.
	entityCh, entitySub, _ := w.registry.WatchEntities(w.ctx)
	defer entitySub.Close()

	var (
		epoch beacon.EpochTime = beacon.EpochInvalid

		reregisterHeight int64 = math.MaxInt64

		first = true
	)
Loop:
	for {
		select {
		case <-w.stopCh:
			return
		case <-w.stopRegCh:
			w.logger.Info("node deregistration and eventual shutdown requested")
			return
		case block := <-blockCh:
			if block.Height < reregisterHeight {
				continue
			}

			// Target re-registration height reached.
			w.logger.Info("re-register height reached for current epoch",
				"epoch", epoch,
				"height", block.Height,
			)
		case epoch = <-ch:
			// Epoch updated, check if we can submit a registration.
			if delayReregistration {
				// Derive the re-registration delay.
				epochHeight, err := w.beacon.GetEpochBlock(w.ctx, epoch)
				switch err {
				case nil:
					// Schedule the re-registration, and wait till the target height.
					reregisterHeight = epochHeight + rand.Int63n(maxReregistrationDelay)
					w.logger.Info("per-epoch re-registration scheduled",
						"epoch_height", epochHeight,
						"target_height", reregisterHeight,
					)
					continue
				default:
					w.logger.Error("failed to query block height for epoch",
						"err", err,
						"epoch", epoch,
					)
				}
			}
		case ev := <-entityCh:
			// Entity registration update.
			if !ev.IsRegistration || !ev.Entity.ID.Equal(w.entityID) {
				continue
			}
		case <-w.registerCh:
			// Notification that a role provider has been updated.
		}

		// We need to know the current epoch before we can register.
		if epoch == beacon.EpochInvalid {
			continue
		}

		// Disarm the re-registration delay height.
		reregisterHeight = math.MaxInt64

		// If there are any role providers which are still not ready, we must wait for more
		// notifications.
		hooks, cbs, vers := func() (h []RegisterNodeHook, cbs []RegisterNodeCallback, vers []uint64) {
			w.RLock()
			defer w.RUnlock()

			w.logger.Debug("enumerating role provider hooks")

			for _, rp := range w.roleProviders {
				rp.Lock()
				role := rp.role
				hook := rp.hook
				cb := rp.cb
				ver := rp.version
				rp.Unlock()

				w.logger.Debug("role provider hook",
					"ver", ver,
					"role", role,
					"hook", hook,
					"cb", cb,
				)

				if hook == nil {
					w.logger.Debug("nil hook for role",
						"role", role,
						"ver", ver,
					)
					return nil, nil, nil
				}

				h = append(h, func(n *node.Node) error {
					n.AddRoles(role)
					return hook(n)
				})
				cbs = append(cbs, cb)
				vers = append(vers, ver)
			}
			return
		}()
		if hooks == nil {
			w.logger.Debug("not registering, no role provider hooks")
			continue Loop
		}

		// Check if the entity under which we are registering actually exists.
		ent, err := w.registry.GetEntity(w.ctx, &registry.IDQuery{
			Height: consensus.HeightLatest,
			ID:     w.entityID,
		})
		switch err {
		case nil:
		case registry.ErrNoSuchEntity:
			// Entity does not yet exist.
			w.logger.Warn("deferring registration as the owning entity does not exist",
				"entity_id", w.entityID,
			)
			continue
		default:
			// Unknown error while trying to look up entity.
			w.logger.Error("failed to query owning entity",
				"err", err,
				"entity_id", w.entityID,
			)
			continue
		}

		// Check if we are whitelisted by the entity.
		nodeID := w.identity.NodeSigner.Public()
		var whitelisted bool
		for _, id := range ent.Nodes {
			if id.Equal(nodeID) {
				whitelisted = true
				break
			}
		}
		if !whitelisted {
			w.logger.Warn("deferring registration as the owning entity does not have us in its node list",
				"entity_id", w.entityID,
				"node_id", nodeID,
			)
			continue
		}

		// Package all per-role/runtime hooks into a metahook.
		hook := func(n *node.Node) error {
			for _, hook := range hooks {
				if err = hook(n); err != nil {
					return fmt.Errorf("hook failed: %w", err)
				}
			}
			return nil
		}

		// Attempt a registration.
		if err = regFn(epoch, hook, first); err != nil {
			if first {
				w.logger.Error("failed to register node",
					"err", err,
				)
				// This is by definition a cancellation as the first
				// registration retries until success. So we can avoid
				// another iteration of the loop to figure this out
				// and abort early.
				return
			}
			w.logger.Error("failed to re-register node",
				"err", err,
			)
			continue
		}
		if first {
			close(w.initialRegCh)
			first = false
		}

		// Call any registration callbacks.
		func() {
			w.RLock()
			defer w.RUnlock()

			for i, rp := range w.roleProviders {
				// Only clear the pending callback in case the hook/call have not been modified.
				rp.Lock()
				if rp.version == vers[i] {
					rp.cb = nil
				}
				rp.Unlock()

				if cb := cbs[i]; cb != nil {
					if err := cb(w.ctx); err != nil {
						w.logger.Error("register node callback failed",
							"err", err,
						)
					}
				}
			}
		}()
	}
}

func (w *Worker) metricsWorker() {
	w.logger.Info("delaying metrics worker start until initial registration")
	select {
	case <-w.stopCh:
		return
	case <-w.ctx.Done():
		return
	case <-w.initialRegCh:
	}

	w.logger.Debug("starting metrics worker")

	t := time.NewTicker(periodicMetricsInterval)
	defer t.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-w.ctx.Done():
			return
		case <-t.C:
		}

		// Update metrics.
		epoch, err := w.beacon.GetEpoch(w.ctx, consensus.HeightLatest)
		if err != nil {
			w.logger.Warn("unable to query epoch", "err", err)
			continue
		}
		status, err := w.GetRegistrationStatus(w.ctx)
		if err != nil {
			w.logger.Warn("unable to get registration status", "err", err)
			continue
		}
		nodeStatus := status.NodeStatus
		if nodeStatus == nil {
			w.logger.Debug("skipping node status metrics, empty node status")
			continue
		}

		// Frozen metric.
		switch nodeStatus.IsFrozen() {
		case true:
			workerNodeStatusFrozen.Set(1)
		case false:
			workerNodeStatusFrozen.Set(0)
		}

		// Election eligible metric.
		switch {
		case nodeStatus.ElectionEligibleAfter == 0:
			workerNodeRegistrationEligible.Set(0)
		case nodeStatus.ElectionEligibleAfter >= epoch:
			workerNodeRegistrationEligible.Set(0)
		default:
			workerNodeRegistrationEligible.Set(1)
		}

		// Runtime metrics.
		for _, rt := range w.runtimeRegistry.Runtimes() {
			if !rt.IsManaged() {
				continue
			}

			rtLabel := rt.ID().String()

			faults := nodeStatus.Faults[rt.ID()]
			switch faults {
			case nil:
				// No faults.
				workerNodeRuntimeSuspended.WithLabelValues(rtLabel).Set(0)
				workerNodeStatusFaults.WithLabelValues(rtLabel).Set(0)
			default:
				workerNodeStatusFaults.WithLabelValues(rtLabel).Set(float64(faults.Failures))
				switch faults.IsSuspended(epoch) {
				case true:
					workerNodeRuntimeSuspended.WithLabelValues(rtLabel).Set(1)
				case false:
					workerNodeRuntimeSuspended.WithLabelValues(rtLabel).Set(0)
				}
			}
		}
	}
}

func (w *Worker) doNodeRegistration() {
	defer func() {
		close(w.quitCh)
		workerNodeRegistered.Set(0.0)
	}()

	if !w.storedDeregister {
		w.registrationLoop()
	} else {
		w.logger.Debug("registration disabled, dropping to direct shutdown")
	}

	// Loop broken; shutdown requested.
	//
	// This is the primary driver of the operator gracefully halting the
	// node after the node's registration expires.  To ensure that the
	// deregistration and shutdown occurs, the node will persist the fact
	// that it is mid-shutdown in a flag.
	//
	// Previously, this flag had to be cleared manually by the node operator
	// which, while serving to ensure that the node does not get restarted
	// and re-register, is sub-optimal as it required manual intervention.
	//
	// Instead, if the node is deregistered cleanly, we will clear the flag
	// under the assumption that the operator can configure whatever
	// automation they are using to do the right thing.
	//
	// See: `Worker.registrationStopped()` for where this happens.

	publicKey := w.identity.NodeSigner.Public()

	regCh, sub, err := w.registry.WatchNodes(w.ctx)
	if err != nil {
		w.logger.Error("failed to watch nodes",
			"err", err,
		)
		return
	}
	defer sub.Close()

	// Check if the node is already deregistered.
	_, err = w.registry.GetNode(w.ctx, &registry.IDQuery{ID: publicKey, Height: consensus.HeightLatest})
	if err == registry.ErrNoSuchNode {
		w.registrationStopped()
		return
	}
	if err != nil {
		w.logger.Error("can't get this node from the registry during shutdown wait",
			"err", err,
		)
		return
	}

	w.logger.Info("waiting for node to deregister")
	for {
		select {
		case ev := <-regCh:
			if !ev.IsRegistration && ev.Node.ID.Equal(publicKey) {
				w.registrationStopped()
				return
			}

		case <-w.ctx.Done():
			return

		case <-w.stopCh:
			return
		}
	}
}

func (w *Worker) registrationStopped() {
	w.logger.Info("registration stopped, shutting down")

	// If the registration was stopped via-graceful shutdown, clear the
	// persisted deregister flag.
	//
	// This routine is only called if:
	//  * Registration is never enabled in the first place.
	//  * The node is deregistered when the shutdown request happens.
	//  * The node successfully deregisters.
	if err := SetForcedDeregister(w.store, false); err != nil {
		// Can't do anything about this, and we are mid-teardown, just log.
		w.logger.Error("failed to clear persisted force-deregister",
			"err", err,
		)
	}

	if w.delegate != nil {
		w.delegate.RegistrationStopped()
	}
}

// GetRegistrationStatus returns the node's current registration status.
func (w *Worker) GetRegistrationStatus(ctx context.Context) (*control.RegistrationStatus, error) {
	w.RLock()
	status := new(control.RegistrationStatus)
	*status = w.status
	w.RUnlock()

	if status.Descriptor == nil {
		return status, nil
	}

	ns, err := w.registry.GetNodeStatus(ctx, &registry.IDQuery{ID: status.Descriptor.ID, Height: consensus.HeightLatest})
	if err != nil {
		return nil, err
	}
	status.NodeStatus = ns

	return status, nil
}

// InitialRegistrationCh returns the initial registration channel.
func (w *Worker) InitialRegistrationCh() chan struct{} {
	return w.initialRegCh
}

// NewRoleProvider creates a new role provider slot.
//
// Each part of the code that wishes to contribute something to the node descriptor can use this
// method to ask the registration worker to create a slot. The slot can (later) be toggled to be
// either available or unavailable. An unavailable slot will prevent the node registration from
// taking place.
//
// The returned role provider is in unavailable state.
func (w *Worker) NewRoleProvider(role node.RolesMask) (RoleProvider, error) {
	return w.newRoleProvider(role, nil)
}

// NewRuntimeRoleProvider creates a new runtime role provider slot.
//
// Each part of the code that wishes to contribute something to the node descriptor can use this
// method to ask the registration worker to create a slot. The slot can (later) be toggled to be
// either available or unavailable. An unavailable slot will prevent the node registration from
// taking place.
//
// The returned role provider is in unavailable state.
func (w *Worker) NewRuntimeRoleProvider(role node.RolesMask, runtimeID common.Namespace) (RoleProvider, error) {
	return w.newRoleProvider(role, &runtimeID)
}

func (w *Worker) newRoleProvider(role node.RolesMask, runtimeID *common.Namespace) (RoleProvider, error) {
	w.logger.Debug("new role provider",
		"id", runtimeID,
		"role", role,
	)
	if !role.IsEmptyRole() && !role.IsSingleRole() {
		return nil, fmt.Errorf("registration role mask is non-empty and does not encode a single role: '%s'", role)
	}

	rp := &roleProvider{
		w:         w,
		role:      role,
		runtimeID: runtimeID,
	}
	w.Lock()
	w.roleProviders = append(w.roleProviders, rp)
	w.Unlock()
	return rp, nil
}

func (w *Worker) gatherConsensusAddresses(sentryConsensusAddrs []node.ConsensusAddress) ([]node.ConsensusAddress, error) {
	var consensusAddrs []node.ConsensusAddress
	var err error

	switch len(w.sentryAddresses) > 0 {
	// If sentry nodes are used, use sentry addresses.
	case true:
		consensusAddrs = sentryConsensusAddrs
	// Otherwise gather consensus addresses.
	case false:
		consensusAddrs, err = w.consensus.GetAddresses()
		if err != nil {
			return nil, fmt.Errorf("worker/registration: failed to get validator's consensus address(es): %w", err)
		}
	}

	// Filter out any potentially invalid addresses.
	var validatedAddrs []node.ConsensusAddress
	for _, addr := range consensusAddrs {
		if !addr.ID.IsValid() {
			w.logger.Error("worker/registration: skipping validator address due to invalid ID",
				"addr", addr,
			)
			continue
		}
		if err = registry.VerifyAddress(addr.Address, allowUnroutableAddresses); err != nil {
			w.logger.Error("worker/registration: skipping validator address due to invalid address",
				"addr", addr,
				"err", err,
			)
			continue
		}
		validatedAddrs = append(validatedAddrs, addr)
	}

	if len(validatedAddrs) == 0 {
		return nil, fmt.Errorf("worker/registration: node has no valid consensus addresses")
	}

	return validatedAddrs, nil
}

func (w *Worker) registerNode(epoch beacon.EpochTime, hook RegisterNodeHook) (err error) {
	identityPublic := w.identity.NodeSigner.Public()
	w.logger.Info("performing node (re-)registration",
		"epoch", epoch,
		"node_id", identityPublic.String(),
	)

	nodeDesc := node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         identityPublic,
		EntityID:   w.entityID,
		Expiration: uint64(epoch) + 2,
		TLS: node.TLSInfo{
			PubKey: w.identity.TLSSigner.Public(),
		},
		P2P: node.P2PInfo{
			ID: w.identity.P2PSigner.Public(),
		},
		Consensus: node.ConsensusInfo{
			ID: w.identity.ConsensusSigner.Public(),
		},
		VRF: node.VRFInfo{
			ID: w.identity.VRFSigner.Public(),
		},
		SoftwareVersion: node.SoftwareVersion(version.SoftwareVersion),
	}

	// Update the registration status on successful or failed registration.
	defer func() {
		w.Lock()
		defer w.Unlock()

		switch err {
		case nil:
			w.status.LastAttemptSuccessful = true
			w.status.LastAttemptErrorMessage = ""
			w.status.LastAttempt = time.Now()
			w.status.LastRegistration = w.status.LastAttempt
			w.status.Descriptor = &nodeDesc
		default:
			w.status.LastAttemptSuccessful = false
			w.status.LastAttemptErrorMessage = err.Error()
			w.status.LastAttempt = time.Now()
			if w.status.Descriptor != nil {
				if w.status.Descriptor.Expiration < uint64(epoch) {
					w.status.Descriptor = nil
				}
			}
		}
	}()

	if err = hook(&nodeDesc); err != nil {
		return err
	}

	// Make sure there is at least one role to register for.
	if nodeDesc.Roles.IsEmptyRole() {
		w.logger.Error("not registering: no roles to register for",
			"node_descriptor", nodeDesc,
		)
		return fmt.Errorf("registration: no roles to register for")
	}

	// Sanity check to prevent an invalid registration when no role provider added any runtimes but
	// runtimes are required due to the specified role.
	if nodeDesc.HasRoles(registry.RuntimesRequiredRoles) && len(nodeDesc.Runtimes) == 0 {
		w.logger.Error("not registering: no runtimes provided while runtimes are required",
			"node_descriptor", nodeDesc,
		)
		return fmt.Errorf("registration: no runtimes provided while runtimes are required")
	}

	sentryConsensusAddrs := w.querySentries()

	// Add Consensus Addresses if required.
	if nodeDesc.HasRoles(registry.ConsensusAddressRequiredRoles) {
		addrs, grr := w.gatherConsensusAddresses(sentryConsensusAddrs)
		if grr != nil {
			return fmt.Errorf("error gathering consensus addresses: %w", grr)
		}
		nodeDesc.Consensus.Addresses = addrs
	}

	// Add P2P Addresses if required.
	if nodeDesc.HasRoles(registry.P2PAddressRequiredRoles) {
		nodeDesc.P2P.Addresses = w.p2p.Addresses()
	}

	nodeSigners := []signature.Signer{
		w.registrationSigner,
		w.identity.P2PSigner,
		w.identity.ConsensusSigner,
		w.identity.VRFSigner,
		w.identity.TLSSigner,
	}
	if !w.identity.NodeSigner.Public().Equal(w.registrationSigner.Public()) {
		// In the case where the registration signer is the entity signer
		// then we prepend the node signer so that the descriptor is always
		// signed by the node itself.
		nodeSigners = append([]signature.Signer{w.identity.NodeSigner}, nodeSigners...)
	}

	sigNode, grr := node.MultiSignNode(nodeSigners, registry.RegisterNodeSignatureContext, &nodeDesc)
	if grr != nil {
		w.logger.Error("failed to register node: unable to sign node descriptor",
			"err", grr,
		)
		return fmt.Errorf("unable to sign node descriptor: %w", grr)
	}

	tx := registry.NewRegisterNodeTx(0, nil, sigNode)
	if err = consensus.SignAndSubmitTx(w.ctx, w.consensus, w.registrationSigner, tx); err != nil {
		w.logger.Error("failed to register node",
			"err", err,
		)
		return err
	}

	w.logger.Info("node registered with the registry")
	return nil
}

func (w *Worker) querySentries() []node.ConsensusAddress {
	var consensusAddrs []node.ConsensusAddress
	var err error

	for _, sentryAddr := range w.sentryAddresses {
		var client *sentryClient.Client
		client, err = sentryClient.New(sentryAddr, w.identity)
		if err != nil {
			w.logger.Warn("failed to create client to a sentry node",
				"err", err,
				"sentry_address", sentryAddr,
			)
			continue
		}
		defer client.Close()

		// Query sentry node for addresses.
		sentryAddresses, err := client.GetAddresses(w.ctx)
		if err != nil {
			w.logger.Warn("failed to obtain addresses from sentry node",
				"err", err,
				"sentry_address", sentryAddr,
			)
			continue
		}
		consensusAddrs = append(consensusAddrs, sentryAddresses.Consensus...)
	}

	if len(consensusAddrs) == 0 {
		w.logger.Error("failed to obtain any consensus address from the configured sentry nodes",
			"sentry_addresses", w.sentryAddresses,
		)
	}

	return consensusAddrs
}

// RequestDeregistration requests that the node not register itself in the next epoch.
func (w *Worker) RequestDeregistration() error {
	if !atomic.CompareAndSwapUint32(&w.deregRequested, 0, 1) {
		// Deregistration already requested, don't do anything.
		return nil
	}
	if err := SetForcedDeregister(w.store, true); err != nil {
		w.logger.Error("can't persist deregistration request",
			"err", err,
		)
		// Let them request it again in this case.
		atomic.StoreUint32(&w.deregRequested, 0)
		return err
	}
	close(w.stopRegCh)
	return nil
}

// WillNeverRegister returns true iff the worker will never register.
func (w *Worker) WillNeverRegister() bool {
	return !w.entityID.IsValid() || w.registrationSigner == nil
}

// GetRegistrationSigner loads the signing credentials as configured by this package's flags.
func GetRegistrationSigner(identity *identity.Identity) (signature.PublicKey, signature.Signer, error) {
	var defaultPk signature.PublicKey

	// If the test entity is enabled, use the entity signing key for signing
	// registrations.
	if flags.DebugTestEntity() {
		testEntity, testSigner, _ := entity.TestEntity()
		return testEntity.ID, testSigner, nil
	}

	// Determine the owning entity ID.
	cfgEntityFn := config.GlobalConfig.Registration.Entity
	cfgEntityID := config.GlobalConfig.Registration.EntityID

	switch {
	case cfgEntityFn != "":
		// Attempt to load the entity descriptor.
		entity, err := entity.LoadDescriptor(cfgEntityFn)
		if err != nil {
			return defaultPk, nil, fmt.Errorf("worker/registration: failed to load entity descriptor: %w", err)
		}

		return entity.ID, identity.NodeSigner, nil
	case cfgEntityID != "":
		// Attempt to parse the entity ID.
		var entityID signature.PublicKey
		if err := entityID.UnmarshalText([]byte(cfgEntityID)); err != nil {
			return defaultPk, nil, fmt.Errorf("worker/registration: malformed entity ID: %w", err)
		}

		return entityID, identity.NodeSigner, nil
	default:
		// TODO: There are certain configurations (eg: the test client) that
		// spin up workers, which require a registration worker, but don't
		// need it, and do not have an owning entity.  The registration worker
		// should not be initialized in this case.
		return defaultPk, nil, nil
	}
}

// New constructs a new worker node registration service.
func New(
	beacon beacon.Backend,
	registry registry.Backend,
	identity *identity.Identity,
	consensus consensus.Service,
	p2p p2p.Service,
	workerCommonCfg *workerCommon.Config,
	store *persistent.CommonStore,
	delegate Delegate,
	runtimeRegistry runtimeRegistry.Registry,
) (*Worker, error) {
	logger := logging.GetLogger("worker/registration")

	serviceStore := store.GetServiceStore(DBBucketName)

	entityID, registrationSigner, err := GetRegistrationSigner(identity)
	if err != nil {
		return nil, err
	}

	var storedDeregister bool
	err = serviceStore.GetCBOR(deregistrationRequestStoreKey, &storedDeregister)
	if err != nil && err != persistent.ErrNotFound {
		return nil, err
	}

	w := &Worker{
		workerCommonCfg:    workerCommonCfg,
		store:              serviceStore,
		delegate:           delegate,
		entityID:           entityID,
		sentryAddresses:    workerCommonCfg.SentryAddresses,
		registrationSigner: registrationSigner,
		runtimeRegistry:    runtimeRegistry,
		beacon:             beacon,
		registry:           registry,
		identity:           identity,
		stopCh:             make(chan struct{}),
		quitCh:             make(chan struct{}),
		initialRegCh:       make(chan struct{}),
		stopRegCh:          make(chan struct{}),
		ctx:                context.Background(),
		logger:             logger,
		consensus:          consensus,
		p2p:                p2p,
		registerCh:         make(chan struct{}, 1),
	}

	w.storedDeregister = storedDeregister

	if config.GlobalConfig.Consensus.Validator || config.GlobalConfig.Mode == config.ModeValidator {
		rp, err := w.NewRoleProvider(node.RoleValidator)
		if err != nil {
			return nil, err
		}

		// The consensus validator is available immediately.
		rp.SetAvailable(func(*node.Node) error { return nil })
	}

	return w, nil
}

// Name returns the service name.
func (w *Worker) Name() string {
	return "worker node registration service"
}

// Start starts the registration service.
func (w *Worker) Start() error {
	w.logger.Info("starting node registration service")

	// HACK: This can be ok in certain configurations.
	if w.WillNeverRegister() {
		w.logger.Warn("no entity/signer for this node, registration will NEVER succeed")
		// Make sure the node is stopped on quit and that it can still respond to
		// shutdown requests from the control api.
		go func() {
			select {
			case <-w.stopCh:
			case <-w.stopRegCh:
				w.registrationStopped()
			}
			close(w.quitCh)
		}()
		return nil
	}

	go w.doNodeRegistration()
	if w.workerCommonCfg.MetricsEnabled {
		go w.metricsWorker()
	}

	return nil
}

// Stop halts the service.
func (w *Worker) Stop() {
	if !atomic.CompareAndSwapUint32(&w.stopped, 0, 1) {
		return
	}
	close(w.stopCh)
}

// Quit returns a channel that will be closed when the service terminates.
func (w *Worker) Quit() <-chan struct{} {
	return w.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (w *Worker) Cleanup() {
}

func init() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})
}

func SetForcedDeregister(store *persistent.ServiceStore, deregister bool) error {
	return store.PutCBOR(deregistrationRequestStoreKey, &deregister)
}
