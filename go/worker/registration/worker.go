package registration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/prometheus/client_golang/prometheus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	sentryClient "github.com/oasisprotocol/oasis-core/go/sentry/client"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
)

const (
	workerRegistrationDBBucketName = "worker/registration"

	// CfgRegistrationEntity configures the registration worker entity.
	CfgRegistrationEntity = "worker.registration.entity"
	// CfgDebugRegistrationPrivateKey configures the registration worker private key.
	CfgDebugRegistrationPrivateKey = "worker.registration.debug.private_key"
	// CfgRegistrationForceRegister overrides a previously saved deregistration
	// request.
	CfgRegistrationForceRegister = "worker.registration.force_register"
	// CfgRegistrationRotateCerts sets the number of epochs that a node's TLS
	// certificate should be valid for.
	CfgRegistrationRotateCerts = "worker.registration.rotate_certs"
)

var (
	deregistrationRequestStoreKey = []byte("deregistration requested")

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	allowUnroutableAddresses bool

	workerNodeRegistered = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_worker_node_registered",
			Help: "Is oasis node registered (binary).",
		},
	)

	nodeCollectors = []prometheus.Collector{
		workerNodeRegistered,
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

func (rp *roleProvider) SetAvailable(hook RegisterNodeHook) {
	rp.SetAvailableWithCallback(hook, nil)
}

func (rp *roleProvider) SetAvailableWithCallback(hook RegisterNodeHook, cb RegisterNodeCallback) {
	rp.Lock()
	rp.version++
	rp.hook = hook
	rp.cb = cb
	rp.Unlock()

	rp.w.registerCh <- struct{}{}
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
	p2p             *p2p.P2P
	ctx             context.Context

	// Bandaid: Idempotent Stop for testing.
	stopped      uint32
	stopCh       chan struct{} // closed internally to trigger stop
	quitCh       chan struct{} // closed after stopped
	initialRegCh chan struct{} // closed after initial registration
	stopRegCh    chan struct{} // closed internally to trigger clean registration lapse

	logger    *logging.Logger
	consensus consensus.Backend

	roleProviders []*roleProvider
	registerCh    chan struct{}

	status control.RegistrationStatus
}

// DebugForceallowUnroutableAddresses allows unroutable addresses.
func DebugForceAllowUnroutableAddresses() {
	allowUnroutableAddresses = true
}

func (w *Worker) registrationLoop() { // nolint: gocyclo
	// If we have any sentry nodes, let them know about our TLS certs.
	if len(w.sentryAddresses) > 0 {
		pubKeys := w.identity.GetTLSPubKeys()
		for _, sentryAddr := range w.sentryAddresses {
			pushCerts := func() error {
				client, err := sentryClient.New(sentryAddr, w.identity)
				if err != nil {
					return err
				}
				defer client.Close()

				err = client.SetUpstreamTLSPubKeys(w.ctx, pubKeys)
				if err != nil {
					return err
				}
				return nil
			}

			sched := backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 60)
			err := backoff.Retry(pushCerts, backoff.WithContext(sched, w.ctx))
			if err != nil {
				w.logger.Error("unable to push upstream TLS certificates to sentry node",
					"err", err,
					"sentry_address", sentryAddr,
				)
			}
		}
	}

	// Delay node registration till after the consensus service has
	// finished initial synchronization if applicable.
	if w.consensus != nil {
		select {
		case <-w.stopCh:
			return
		case <-w.consensus.Synced():
		}
	}

	// (re-)register the node on each epoch transition. This doesn't
	// need to be strict block-epoch time, since it just serves to
	// extend the node's expiration.
	ch, sub := w.beacon.WatchLatestEpoch()
	defer sub.Close()

	regFn := func(epoch beacon.EpochTime, hook RegisterNodeHook, retry bool) error {
		var off backoff.BackOff

		switch retry {
		case true:
			expBackoff := backoff.NewExponentialBackOff()
			expBackoff.MaxElapsedTime = 0
			off = expBackoff
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
				return context.Canceled
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
		epoch                beacon.EpochTime
		lastTLSRotationEpoch beacon.EpochTime

		tlsRotationPending = true
		first              = true
	)
Loop:
	for {
		select {
		case <-w.stopCh:
			return
		case <-w.stopRegCh:
			w.logger.Info("node deregistration and eventual shutdown requested")
			return
		case epoch = <-ch:
			// Epoch updated, check if we can submit a registration.

			// Check if we need to rotate the node's TLS certificate.
			if !w.identity.DoNotRotateTLS && !tlsRotationPending {
				// Per how many epochs should we do rotations?
				// TODO: Make this time-based instead.
				rotateTLSCertsPer := beacon.EpochTime(viper.GetUint64(CfgRegistrationRotateCerts))
				if rotateTLSCertsPer != 0 && (epoch-lastTLSRotationEpoch) >= rotateTLSCertsPer {
					// Rotate node TLS certificates.
					err := w.identity.RotateCertificates()
					if err != nil {
						w.logger.Error("node TLS certificate rotation failed",
							"new_epoch", epoch,
							"err", err,
						)
					} else {
						pub1 := w.identity.GetTLSSigner().Public()
						pub2 := w.identity.GetNextTLSSigner().Public()
						tlsRotationPending = true

						w.logger.Info("node TLS certificates have been rotated",
							"new_epoch", epoch,
							"new_pub1", accessctl.SubjectFromPublicKey(pub1),
							"new_pub2", accessctl.SubjectFromPublicKey(pub2),
						)
					}
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

		// If there are any role providers which are still not ready, we must wait for more
		// notifications.
		hooks, cbs, vers := func() (h []RegisterNodeHook, cbs []RegisterNodeCallback, vers []uint64) {
			w.RLock()
			defer w.RUnlock()

			for _, rp := range w.roleProviders {
				rp.Lock()
				role := rp.role
				hook := rp.hook
				cb := rp.cb
				ver := rp.version
				rp.Unlock()

				if hook == nil {
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
			continue Loop
		}

		// Check if the entity under which we are registering actually exists.
		_, err := w.registry.GetEntity(w.ctx, &registry.IDQuery{
			Height: consensus.HeightLatest,
			ID:     w.entityID,
		})
		switch err {
		case nil:
		case registry.ErrNoSuchEntity:
			// Entity does not yet exist.
			w.logger.Warn("defering registration as the owning entity does not exist",
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

		// Do not perform TLS rotation unless we have successfully (re-)registered.
		if tlsRotationPending {
			lastTLSRotationEpoch = epoch
			tlsRotationPending = false
		}
	}
}

func (w *Worker) doNodeRegistration() {
	defer close(w.quitCh)
	defer workerNodeRegistered.Set(0.0)

	if !w.storedDeregister {
		w.registrationLoop()
	}

	// Loop broken; shutdown requested.
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
	if w.delegate != nil {
		w.delegate.RegistrationStopped()
	}
}

// GetRegistrationStatus returns the node's current registration status.
func (w *Worker) GetRegistrationStatus(ctx context.Context) (*control.RegistrationStatus, error) {
	w.RLock()
	defer w.RUnlock()

	status := new(control.RegistrationStatus)
	*status = w.status
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
	if !role.IsSingleRole() {
		return nil, fmt.Errorf("RegisterRole: registration role mask does not encode a single role. RoleMask: '%s'", role)
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

func (w *Worker) gatherTLSAddresses(sentryTLSAddrs []node.TLSAddress) ([]node.TLSAddress, error) {
	var tlsAddresses []node.TLSAddress

	switch len(w.sentryAddresses) > 0 {
	// If sentry nodes are used, use sentry addresses.
	case true:
		tlsAddresses = sentryTLSAddrs
	// Otherwise gather TLS addresses.
	case false:
		addrs, err := w.workerCommonCfg.GetNodeAddresses()
		if err != nil {
			return nil, fmt.Errorf("worker/registration: failed to register node: unable to get node addresses: %w", err)
		}
		for _, addr := range addrs {
			tlsAddresses = append(tlsAddresses, node.TLSAddress{
				PubKey:  w.identity.GetTLSSigner().Public(),
				Address: addr,
			})
			// Make sure to also include the certificate that will be valid
			// in the next epoch, so that the node remains reachable.
			if nextSigner := w.identity.GetNextTLSSigner(); nextSigner != nil {
				tlsAddresses = append(tlsAddresses, node.TLSAddress{
					PubKey:  nextSigner.Public(),
					Address: addr,
				})
			}
		}
	}

	// Filter out any potentially invalid addresses.
	var validatedAddrs []node.TLSAddress
	for _, addr := range tlsAddresses {
		if !addr.PubKey.IsValid() {
			w.logger.Error("worker/registration: skipping node address due to invalid public key",
				"addr", addr,
			)
			continue
		}

		if err := registry.VerifyAddress(addr.Address, allowUnroutableAddresses); err != nil {
			w.logger.Error("worker/registration: skipping node address due to invalid address",
				"addr", addr,
				"err", err,
			)
			continue
		}
		validatedAddrs = append(validatedAddrs, addr)
	}

	if len(validatedAddrs) == 0 {
		return nil, fmt.Errorf("worker/registration: node has no valid TLS addresses")
	}

	return validatedAddrs, nil
}

func (w *Worker) registerNode(epoch beacon.EpochTime, hook RegisterNodeHook) error {
	identityPublic := w.identity.NodeSigner.Public()
	w.logger.Info("performing node (re-)registration",
		"epoch", epoch,
		"node_id", identityPublic.String(),
	)

	var nextPubKey signature.PublicKey
	if s := w.identity.GetNextTLSSigner(); s != nil {
		nextPubKey = s.Public()
	}

	nodeDesc := node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         identityPublic,
		EntityID:   w.entityID,
		Expiration: uint64(epoch) + 2,
		TLS: node.TLSInfo{
			PubKey:     w.identity.GetTLSSigner().Public(),
			NextPubKey: nextPubKey,
		},
		P2P: node.P2PInfo{
			ID: w.identity.P2PSigner.Public(),
		},
		Consensus: node.ConsensusInfo{
			ID: w.identity.ConsensusSigner.Public(),
		},
		Beacon: &node.BeaconInfo{
			Point: w.identity.BeaconScalar.Point(),
		},
	}

	if err := hook(&nodeDesc); err != nil {
		return err
	}

	// Sanity check to prevent an invalid registration when no role provider added any runtimes but
	// runtimes are required due to the specified role.
	if nodeDesc.HasRoles(registry.RuntimesRequiredRoles) && len(nodeDesc.Runtimes) == 0 {
		w.logger.Error("not registering: no runtimes provided while runtimes are required",
			"node_descriptor", nodeDesc,
		)
		return fmt.Errorf("registration: no runtimes provided while runtimes are required")
	}

	var sentryConsensusAddrs []node.ConsensusAddress
	var sentryTLSAddrs []node.TLSAddress
	if len(w.sentryAddresses) > 0 {
		sentryConsensusAddrs, sentryTLSAddrs = w.querySentries()
	}

	// Add Consensus Addresses if required.
	if nodeDesc.HasRoles(registry.ConsensusAddressRequiredRoles) {
		addrs, err := w.gatherConsensusAddresses(sentryConsensusAddrs)
		if err != nil {
			return fmt.Errorf("error gathering consensus addresses: %w", err)
		}
		nodeDesc.Consensus.Addresses = addrs
	}

	// Add TLS Addresses if required.
	if nodeDesc.HasRoles(registry.TLSAddressRequiredRoles) {
		addrs, err := w.gatherTLSAddresses(sentryTLSAddrs)
		if err != nil {
			return fmt.Errorf("error gathering TLS addresses: %w", err)
		}
		nodeDesc.TLS.Addresses = addrs
	}

	// Add P2P Addresses if required.
	if nodeDesc.HasRoles(registry.P2PAddressRequiredRoles) {
		nodeDesc.P2P.Addresses = w.p2p.Addresses()
	}

	nodeSigners := []signature.Signer{
		w.registrationSigner,
		w.identity.P2PSigner,
		w.identity.ConsensusSigner,
		w.identity.GetTLSSigner(),
	}
	if !w.identity.NodeSigner.Public().Equal(w.registrationSigner.Public()) {
		// In the case where the registration signer is the entity signer
		// then we prepend the node signer so that the descriptor is always
		// signed by the node itself.
		nodeSigners = append([]signature.Signer{w.identity.NodeSigner}, nodeSigners...)
	}

	sigNode, err := node.MultiSignNode(nodeSigners, registry.RegisterNodeSignatureContext, &nodeDesc)
	if err != nil {
		w.logger.Error("failed to register node: unable to sign node descriptor",
			"err", err,
		)
		return err
	}

	tx := registry.NewRegisterNodeTx(0, nil, sigNode)
	if err := consensus.SignAndSubmitTx(w.ctx, w.consensus, w.registrationSigner, tx); err != nil {
		w.logger.Error("failed to register node",
			"err", err,
		)
		return err
	}

	// Update the registration status on successful registration.
	w.RLock()
	w.status.LastRegistration = time.Now()
	w.status.Descriptor = &nodeDesc
	w.RUnlock()

	w.logger.Info("node registered with the registry")
	return nil
}

func (w *Worker) querySentries() ([]node.ConsensusAddress, []node.TLSAddress) {
	var consensusAddrs []node.ConsensusAddress
	var tlsAddrs []node.TLSAddress
	var err error

	pubKeys := w.identity.GetTLSPubKeys()
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

		// Keep sentries updated with our latest TLS certificates.
		err = client.SetUpstreamTLSPubKeys(w.ctx, pubKeys)
		if err != nil {
			w.logger.Warn("failed to provide upstream TLS certificates to sentry node",
				"err", err,
				"sentry_address", sentryAddr,
			)
		}

		consensusAddrs = append(consensusAddrs, sentryAddresses.Consensus...)
		tlsAddrs = append(tlsAddrs, sentryAddresses.TLS...)
	}

	if len(consensusAddrs) == 0 {
		w.logger.Error("failed to obtain any consensus address from the configured sentry nodes",
			"sentry_addresses", w.sentryAddresses,
		)
	}
	if len(tlsAddrs) == 0 {
		w.logger.Error("failed to obtain any TLS address from the configured sentry nodes",
			"sentry_addresses", w.sentryAddresses,
		)
	}

	return consensusAddrs, tlsAddrs
}

// RequestDeregistration requests that the node not register itself in the next epoch.
func (w *Worker) RequestDeregistration() error {
	if !atomic.CompareAndSwapUint32(&w.deregRequested, 0, 1) {
		// Deregistration already requested, don't do anything.
		return nil
	}
	storedDeregister := true
	err := w.store.PutCBOR(deregistrationRequestStoreKey, &storedDeregister)
	if err != nil {
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

// GetRegistrationSigner loads the signing credentials as configured by this package's flags.
func GetRegistrationSigner(logger *logging.Logger, dataDir string, identity *identity.Identity) (signature.PublicKey, signature.Signer, error) {
	var defaultPk signature.PublicKey

	// If the test entity is enabled, use the entity signing key for signing
	// registrations.
	if flags.DebugTestEntity() {
		testEntity, testSigner, _ := entity.TestEntity()
		return testEntity.ID, testSigner, nil
	}

	// Load the registration entity descriptor.
	f := viper.GetString(CfgRegistrationEntity)
	if f == "" {
		// TODO: There are certain configurations (eg: the test client) that
		// spin up workers, which require a registration worker, but don't
		// need it, and do not have an owning entity.  The registration worker
		// should not be initialized in this case.
		return defaultPk, nil, nil
	}

	// Attempt to load the entity descriptor.
	entity, err := entity.LoadDescriptor(f)
	if err != nil {
		return defaultPk, nil, fmt.Errorf("worker/registration: failed to load entity descriptor: %w", err)
	}
	if !entity.AllowEntitySignedNodes {
		// If the entity does not allow any entity-signed nodes, then
		// registrations will always be node-signed.
		return entity.ID, identity.NodeSigner, nil
	}
	for _, v := range entity.Nodes {
		if v.Equal(identity.NodeSigner.Public()) {
			// If the node is in the entity's list of allowed nodes
			// then registrations MUST be node-signed.
			return entity.ID, identity.NodeSigner, nil
		}
	}

	if !flags.DebugDontBlameOasis() {
		return defaultPk, nil, fmt.Errorf("worker/registration: entity signed nodes disallowed by node config")
	}

	// At this point, the entity allows entity-signed registrations,
	// and the node is not in the entity's list of allowed
	// node-signed nodes.
	//
	// TODO: The only reason why an entity descriptor ever needs to
	// be provided, is for this check.  It would be better for the common
	// case to just query the entity descriptor from the registry,
	// given a entity ID.

	// The entity allows self-signed nodes, try to load the entity private key.
	f = viper.GetString(CfgDebugRegistrationPrivateKey)
	if f == "" {
		// If the private key is not provided, try using a node-signed
		// registration, the local copy of the entity descriptor may
		// just be stale.
		logger.Warn("no entity signing key provided, falling back to the node identity key")

		return entity.ID, identity.NodeSigner, nil
	}

	logger.Warn("using the entity signing key for node registration")

	factory, err := fileSigner.NewFactory(dataDir, signature.SignerEntity)
	if err != nil {
		return defaultPk, nil, fmt.Errorf("worker/registration: failed to create entity signer factory: %w", err)
	}
	fileFactory := factory.(*fileSigner.Factory)
	entitySigner, err := fileFactory.ForceLoad(f)
	if err != nil {
		return defaultPk, nil, fmt.Errorf("worker/registration: failed to load entity signing key: %w", err)
	}

	return entity.ID, entitySigner, nil
}

// New constructs a new worker node registration service.
func New(
	dataDir string,
	beacon beacon.Backend,
	registry registry.Backend,
	identity *identity.Identity,
	consensus consensus.Backend,
	p2p *p2p.P2P,
	workerCommonCfg *workerCommon.Config,
	store *persistent.CommonStore,
	delegate Delegate,
	runtimeRegistry runtimeRegistry.Registry,
) (*Worker, error) {
	logger := logging.GetLogger("worker/registration")

	serviceStore, err := store.GetServiceStore(workerRegistrationDBBucketName)
	if err != nil {
		logger.Error("can't get registration worker store bucket",
			"err", err,
		)
		return nil, err
	}

	entityID, registrationSigner, err := GetRegistrationSigner(logger, dataDir, identity)
	if err != nil {
		return nil, err
	}

	storedDeregister := false
	err = serviceStore.GetCBOR(deregistrationRequestStoreKey, &storedDeregister)
	if err != nil && err != persistent.ErrNotFound {
		return nil, err
	}

	if viper.GetBool(CfgRegistrationForceRegister) {
		storedDeregister = false
		err = serviceStore.PutCBOR(deregistrationRequestStoreKey, &storedDeregister)
		if err != nil {
			return nil, err
		}
	}

	if viper.GetUint64(CfgRegistrationRotateCerts) != 0 && identity.DoNotRotateTLS {
		return nil, fmt.Errorf("node TLS certificate rotation must not be enabled if using pre-generated TLS certificates")
	}

	w := &Worker{
		workerCommonCfg:    workerCommonCfg,
		store:              serviceStore,
		storedDeregister:   storedDeregister,
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
		registerCh:         make(chan struct{}, 64),
	}

	if flags.ConsensusValidator() {
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
	if !w.entityID.IsValid() || w.registrationSigner == nil {
		w.logger.Warn("no entity/signer for this node, registration will NEVER succeed")
		// Make sure the node is stopped on quit.
		go func() {
			<-w.stopCh
			close(w.quitCh)
		}()
		return nil
	}

	go w.doNodeRegistration()

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

	Flags.String(CfgRegistrationEntity, "", "entity to use as the node owner in registrations")
	Flags.String(CfgDebugRegistrationPrivateKey, "", "private key to use to sign node registrations")
	Flags.Bool(CfgRegistrationForceRegister, false, "override a previously saved deregistration request")
	Flags.Uint64(CfgRegistrationRotateCerts, 0, "rotate node TLS certificates every N epochs (0 to disable)")
	_ = Flags.MarkHidden(CfgDebugRegistrationPrivateKey)

	_ = viper.BindPFlags(Flags)
}
