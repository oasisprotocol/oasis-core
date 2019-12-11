package registration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/persistent"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	sentryClient "github.com/oasislabs/oasis-core/go/sentry/client"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
)

const (
	workerRegistrationDBBucketName = "worker/registration"

	// CfgRegistrationEntity configures the registration worker entity.
	CfgRegistrationEntity = "worker.registration.entity"
	// CfgRegistrationPrivateKey configures the registration worker private key.
	CfgRegistrationPrivateKey = "worker.registration.private_key"
	// CfgRegistrationForceRegister overrides a previously saved deregistration request.
	CfgRegistrationForceRegister = "worker.registration.force_register"
)

var (
	deregistrationRequestStoreKey = []byte("deregistration requested")

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	allowUnroutableAddresses bool
)

// Delegate is the interface for objects that wish to know about the worker's events.
type Delegate interface {
	// RegistrationStopped is called by the worker when the registration loop exits cleanly.
	RegistrationStopped()
}

// Worker is a service handling worker node registration.
type Worker struct { // nolint: maligned
	sync.Mutex

	workerCommonCfg *workerCommon.Config

	store            *persistent.ServiceStore
	storedDeregister bool
	delegate         Delegate

	entityID           signature.PublicKey
	registrationSigner signature.Signer

	epochtime epochtime.Backend
	registry  registry.Backend
	identity  *identity.Identity
	p2p       *p2p.P2P
	ctx       context.Context

	// Bandaid: Idempotent Stop for testing.
	stopped      uint32
	stopCh       chan struct{} // closed internally to trigger stop
	quitCh       chan struct{} // closed after stopped
	initialRegCh chan struct{} // closed after initial registration
	stopReqCh    chan struct{} // closed internally to trigger clean registration lapse

	logger    *logging.Logger
	roleHooks map[node.RolesMask](func(*node.Node) error)
	consensus consensus.Backend
}

// DebugForceallowUnroutableAddresses allows unroutable addresses.
func DebugForceAllowUnroutableAddresses() {
	allowUnroutableAddresses = true
}

func (w *Worker) registrationLoop() {
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
	ch, sub := w.epochtime.WatchEpochs()
	defer sub.Close()

	regFn := func(epoch epochtime.EpochTime, retry bool) error {
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

			return w.registerNode(epoch)
		}, off)
	}

	first := true
Loop:
	for {
		select {
		case <-w.stopCh:
			return
		case epoch := <-ch:
			// Check first if a clean halt was requested.
			select {
			case <-w.stopReqCh:
				w.logger.Info("node deregistration and eventual shutdown requested")
				w.Stop()
				break Loop
			default:
			}

			if err := regFn(epoch, first); err != nil {
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
		}
	}
}

func (w *Worker) doNodeRegistration() {
	defer close(w.quitCh)

	if !w.storedDeregister {
		w.registrationLoop()
	}

	// Loop broken; shutdown requested.
	publicKey := w.identity.NodeSigner.Public()

	initialRegCh, sub := w.registry.WatchNodes()
	defer sub.Close()

	// Check if the node is already deregistered.
	_, err := w.registry.GetNode(w.ctx, publicKey, 0)
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
		case ev := <-initialRegCh:
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

// InitialRegistrationCh returns the initial registration channel.
func (w *Worker) InitialRegistrationCh() chan struct{} {
	return w.initialRegCh
}

// RegisterRole enables registering Node roles. Only one hook per role is
// allowed.
//
// hook is a callback that can be used to update node descriptor with role
// specific settings, e.g. setting compute capabilities for compute worker.
func (w *Worker) RegisterRole(role node.RolesMask, hook func(*node.Node) error) error {
	w.Lock()
	defer w.Unlock()

	if !role.IsSingleRole() {
		return fmt.Errorf("RegisterRole: registration role mask does not encode a single role. RoleMask: '%s'", role)
	}

	if _, exists := w.roleHooks[role]; exists {
		return fmt.Errorf("RegisterRole: role already registered. Role: '%s'", role)
	}
	w.roleHooks[role] = hook

	return nil
}

func (w *Worker) registerNode(epoch epochtime.EpochTime) error {
	w.logger.Info("performing node (re-)registration",
		"epoch", epoch,
	)

	identityPublic := w.identity.NodeSigner.Public()
	nodeDesc := node.Node{
		ID:         identityPublic,
		EntityID:   w.entityID,
		Expiration: uint64(epoch) + 2,
		Committee: node.CommitteeInfo{
			Certificate: w.identity.TLSCertificate.Certificate[0],
		},
		P2P: node.P2PInfo{
			ID: w.identity.P2PSigner.Public(),
		},
		Consensus: node.ConsensusInfo{
			ID: w.consensus.ConsensusKey(),
		},
	}
	for role := range w.roleHooks {
		nodeDesc.AddRoles(role)
	}
	if nodeDesc.HasRoles(registry.RuntimesRequiredRoles) {
		for _, runtime := range w.workerCommonCfg.Runtimes {
			nodeDesc.Runtimes = append(nodeDesc.Runtimes, &node.Runtime{
				ID: runtime,
			})
		}
	}

	w.Lock()
	defer w.Unlock()

	// Apply worker role hooks:
	for role, h := range w.roleHooks {
		if err := h(&nodeDesc); err != nil {
			w.logger.Error("failed to apply role hook",
				"role", role,
				"err", err,
			)
		}
	}

	// Add Committee Addresses if required.
	if nodeDesc.HasRoles(registry.CommitteeAddressRequiredRoles) {
		addresses, err := w.workerCommonCfg.GetNodeAddresses()
		if err != nil {
			w.logger.Error("failed to register node: unable to get committee addresses",
				"err", err,
			)
			return err
		}

		nodeDesc.Committee.Addresses = addresses
	}

	// Add P2P Addresses if required.
	if nodeDesc.HasRoles(registry.P2PAddressRequiredRoles) {
		nodeDesc.P2P.Addresses = w.p2p.Addresses()
	}

	// Only register node if hooks exist.
	if len(w.roleHooks) > 0 {
		signedNode, err := node.SignNode(w.registrationSigner, registry.RegisterNodeSignatureContext, &nodeDesc)
		if err != nil {
			w.logger.Error("failed to register node: unable to sign node descriptor",
				"err", err,
			)
			return err
		}

		tx := registry.NewRegisterNodeTx(0, nil, signedNode)
		if err := consensus.SignAndSubmitTx(w.ctx, w.consensus, w.registrationSigner, tx); err != nil {
			w.logger.Error("failed to register node",
				"err", err,
			)
			return err
		}

		w.logger.Info("node registered with the registry")
	} else {
		w.logger.Info("skipping node registration as no registerted role hooks")
	}

	return nil
}

func (w *Worker) consensusValidatorHook(n *node.Node) error {
	var addrs []node.ConsensusAddress
	var err error
	sentryAddrs := w.workerCommonCfg.SentryAddresses
	sentryCerts := w.workerCommonCfg.SentryCertificates
	if len(sentryAddrs) > 0 {
		// Query sentry nodes for their consensus address(es).
		for i, sentryAddr := range sentryAddrs {
			var client *sentryClient.Client
			client, err = sentryClient.New(&sentryAddr, sentryCerts[i], w.identity)
			if err != nil {
				w.logger.Warn("failed to create client to a sentry node",
					"err", err,
					"sentry_address", sentryAddr,
				)
				continue
			}
			defer client.Close()
			var consensusAddrs []node.ConsensusAddress
			consensusAddrs, err = client.GetConsensusAddresses(w.ctx)
			if err != nil {
				w.logger.Warn("failed to obtain consensus address(es) from sentry node",
					"err", err,
					"sentry_address", sentryAddr,
				)
				continue
			}
			addrs = append(addrs, consensusAddrs...)
		}
		if len(addrs) == 0 {
			errMsg := "failed to obtain any consensus address from the configured sentry nodes"
			w.logger.Error(errMsg,
				"sentry_addresses", sentryAddrs,
			)
			return fmt.Errorf(errMsg)
		}
	} else {
		// Use validator's consensus address(es).
		addrs, err = w.consensus.GetAddresses()
		if err != nil {
			return fmt.Errorf("worker/registration: failed to get validator's consensus address(es): %w", err)
		}
	}

	var validatedAddrs []node.ConsensusAddress
	for _, addr := range addrs {
		if !addr.ID.IsValid() {
			w.logger.Error("worker/registration: skipping validator address due to invalid ID",
				"addr", addr,
			)
			continue
		}
		if err := registry.VerifyAddress(addr.Address, allowUnroutableAddresses); err != nil {
			w.logger.Error("worker/registration: skipping validator address due to invalid address",
				"addr", addr,
				"err", err,
			)
			continue
		}
		validatedAddrs = append(validatedAddrs, addr)
	}

	if len(validatedAddrs) == 0 {
		return fmt.Errorf("worker/registration: node has no consensus addresses")
	}

	// n.Consensus.ID is set for all nodes, no need to set it here.
	n.Consensus.Addresses = validatedAddrs

	return nil
}

// RequestDeregistration requests that the node not register itself in the next epoch.
func (w *Worker) RequestDeregistration() {
	storedDeregister := true
	err := w.store.PutCBOR(deregistrationRequestStoreKey, &storedDeregister)
	if err != nil {
		w.logger.Error("can't persist deregistration request",
			"err", err,
		)
	}
	close(w.stopReqCh)
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
		return defaultPk, nil, errors.Wrap(err, "worker/registration: failed to load entity descriptor")
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

	// At this point, the entity allows entity-signed registrations,
	// and the node is not in the entity's list of allowed
	// node-signed nodes.
	//
	// TODO: The only reason why an entity descriptor ever needs to
	// be provided, is for this check.  It would be better for the common
	// case to just query the entity descriptor from the registry,
	// given a entity ID.

	// The entity allows self-signed nodes, try to load the entity private key.
	f = viper.GetString(CfgRegistrationPrivateKey)
	if f == "" {
		// If the private key is not provided, try using a node-signed
		// registration, the local copy of the entity descriptor may
		// just be stale.
		logger.Warn("no entity signing key provided, falling back to the node identity key")

		return entity.ID, identity.NodeSigner, nil
	}

	logger.Warn("using the entity signing key for node registration")

	factory := fileSigner.NewFactory(dataDir, signature.SignerEntity)
	fileFactory := factory.(*fileSigner.Factory)
	entitySigner, err := fileFactory.ForceLoad(f)
	if err != nil {
		return defaultPk, nil, errors.Wrap(err, "worker/registration: failed to load entity signing key")
	}

	return entity.ID, entitySigner, nil
}

// New constructs a new worker node registration service.
func New(
	dataDir string,
	epochtime epochtime.Backend,
	registry registry.Backend,
	identity *identity.Identity,
	consensus consensus.Backend,
	p2p *p2p.P2P,
	workerCommonCfg *workerCommon.Config,
	store *persistent.CommonStore,
	delegate Delegate,
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

	w := &Worker{
		workerCommonCfg:    workerCommonCfg,
		store:              serviceStore,
		storedDeregister:   storedDeregister,
		delegate:           delegate,
		entityID:           entityID,
		registrationSigner: registrationSigner,
		epochtime:          epochtime,
		registry:           registry,
		identity:           identity,
		stopCh:             make(chan struct{}),
		quitCh:             make(chan struct{}),
		initialRegCh:       make(chan struct{}),
		stopReqCh:          make(chan struct{}),
		ctx:                context.Background(),
		logger:             logger,
		consensus:          consensus,
		p2p:                p2p,
		roleHooks:          make(map[node.RolesMask](func(*node.Node) error)),
	}

	if flags.ConsensusValidator() {
		if err := w.RegisterRole(node.RoleValidator, w.consensusValidatorHook); err != nil {
			return nil, err
		}
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
	Flags.String(CfgRegistrationEntity, "", "Entity to use as the node owner in registrations")
	Flags.String(CfgRegistrationPrivateKey, "", "Private key to use to sign node registrations")
	Flags.Bool(CfgRegistrationForceRegister, false, "Override a previously saved deregistration request")

	_ = viper.BindPFlags(Flags)
}
