package registration

import (
	"context"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/consensus"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
)

const (
	// CfgRegistrationEntity configures the registration worker entity.
	CfgRegistrationEntity = "worker.registration.entity"
	// CfgRegistrationPrivateKey configures the registration worker private key.
	CfgRegistrationPrivateKey = "worker.registration.private_key"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Worker is a service handling worker node registration.
type Worker struct {
	sync.Mutex

	workerCommonCfg *workerCommon.Config

	entityID           signature.PublicKey
	registrationSigner signature.Signer

	epochtime epochtime.Backend
	registry  registry.Backend
	identity  *identity.Identity
	p2p       *p2p.P2P
	ctx       context.Context
	// Bandaid: Idempotent Stop for testing.
	stopped   bool
	stopCh    chan struct{}
	quitCh    chan struct{}
	regCh     chan struct{}
	logger    *logging.Logger
	roleHooks []func(*node.Node) error
	consensus consensus.Backend
}

func (w *Worker) doNodeRegistration() {
	defer close(w.quitCh)

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
	for {
		select {
		case <-w.stopCh:
			return
		case epoch := <-ch:
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
				close(w.regCh)
				first = false
			}
		}
	}
}

// InitialRegistrationCh returns the initial registration channel.
func (w *Worker) InitialRegistrationCh() chan struct{} {
	return w.regCh
}

// RegisterRole enables registering Node roles.
// hook is a callback that does the following:
// - Use AddRole to add a role to the node descriptor
// - Make other changes specific to the role, e.g. setting compute capabilities
func (w *Worker) RegisterRole(hook func(*node.Node) error) {
	w.Lock()
	defer w.Unlock()

	w.roleHooks = append(w.roleHooks, hook)
}

func (w *Worker) registerNode(epoch epochtime.EpochTime) error {
	w.logger.Info("performing node (re-)registration",
		"epoch", epoch,
	)

	addresses, err := w.workerCommonCfg.GetNodeAddresses()
	if err != nil {
		w.logger.Error("failed to register node: unable to get addresses",
			"err", err,
		)
		return err
	}
	identityPublic := w.identity.NodeSigner.Public()
	nodeDesc := node.Node{
		ID:         identityPublic,
		EntityID:   w.entityID,
		Expiration: uint64(epoch) + 2,
		Committee: node.CommitteeInfo{
			Certificate: w.identity.TLSCertificate.Certificate[0],
			Addresses:   addresses,
		},
		P2P: w.p2p.Info(),
		Consensus: node.ConsensusInfo{
			ID: w.consensus.ConsensusKey(),
		},
		RegistrationTime: uint64(time.Now().Unix()),
	}
	for _, runtime := range w.workerCommonCfg.Runtimes {
		nodeDesc.Runtimes = append(nodeDesc.Runtimes, &node.Runtime{
			ID: runtime,
		})
	}

	w.Lock()
	defer w.Unlock()

	// Apply worker role hooks:
	for _, h := range w.roleHooks {
		if err := h(&nodeDesc); err != nil {
			w.logger.Error("failed to apply role hook",
				"err", err)
		}
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
		if err := w.registry.RegisterNode(w.ctx, signedNode); err != nil {
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
	addrs, err := w.consensus.GetAddresses()
	if err != nil {
		return errors.Wrap(err, "worker/registration: failed to get consensus validator addresses")
	}

	if len(addrs) == 0 {
		w.logger.Error("node has no consensus addresses, not registering as validator")
		return nil
	}

	// TODO: Someone, somewhere needs to check to see if the address is
	// actually routable (or applicable for a given configuration).  My
	// inclination is to do it in the registry, but this would be the other
	// location for such a thing.

	// n.Consensus.ID is set for all nodes, no need to set it here.
	n.Consensus.Addresses = addrs
	n.AddRoles(node.RoleValidator)

	return nil
}

// GetRegistrationSigner loads the signing credentials as configured by this package's flags.
func GetRegistrationSigner(logger *logging.Logger, dataDir string, identity *identity.Identity) (signature.PublicKey, signature.Signer, error) {
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
		return nil, nil, nil
	}

	// Attempt to load the entity descriptor.
	entity, err := entity.LoadDescriptor(f)
	if err != nil {
		return nil, nil, errors.Wrap(err, "worker/registration: failed to load entity descriptor")
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
		return nil, nil, errors.Wrap(err, "worker/registration: failed to load entity signing key")
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
) (*Worker, error) {
	logger := logging.GetLogger("worker/registration")

	entityID, registrationSigner, err := GetRegistrationSigner(logger, dataDir, identity)
	if err != nil {
		return nil, err
	}

	w := &Worker{
		workerCommonCfg:    workerCommonCfg,
		entityID:           entityID,
		registrationSigner: registrationSigner,
		epochtime:          epochtime,
		registry:           registry,
		identity:           identity,
		stopCh:             make(chan struct{}),
		quitCh:             make(chan struct{}),
		regCh:              make(chan struct{}),
		ctx:                context.Background(),
		logger:             logger,
		consensus:          consensus,
		p2p:                p2p,
		roleHooks:          []func(*node.Node) error{},
	}

	if flags.ConsensusValidator() {
		w.RegisterRole(w.consensusValidatorHook)
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
	if w.entityID == nil || w.registrationSigner == nil {
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
	if w.stopped {
		return
	}
	w.stopped = true
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

	_ = viper.BindPFlags(Flags)
}
