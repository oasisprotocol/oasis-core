package oasis

import (
	"fmt"
	"os"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
)

const (
	observerIdentitySeedTemplate = "ekiden node observer %d"
)

// Observer is an Oasis observer node.
type Observer struct {
	*Node

	consensusPort uint16
	p2pPort       uint16

	runtimes           []int
	runtimeConfig      map[int]map[string]any
	runtimeProvisioner runtimeConfig.RuntimeProvisioner
}

// ObserverCfg is the Oasis observer node provisioning configuration.
type ObserverCfg struct {
	NodeCfg

	Runtimes           []int
	RuntimeConfig      map[int]map[string]any
	RuntimeProvisioner runtimeConfig.RuntimeProvisioner
}

// UpdateRuntimes updates the observer node runtimes.
func (o *Observer) UpdateRuntimes(runtimes []int) {
	o.runtimes = runtimes
}

func (o *Observer) AddArgs(args *argBuilder) error {
	args.appendNetwork(o.net)

	if o.entity.isDebugTestEntity {
		args.appendDebugTestEntity()
	}

	for _, idx := range o.runtimes {
		v := o.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		o.addHostedRuntime(v, o.runtimeConfig[idx])
	}

	return nil
}

func (o *Observer) ModifyConfig() error {
	o.Config.Consensus.ListenAddress = allInterfacesAddr + ":" + strconv.Itoa(int(o.consensusPort))
	o.Config.Consensus.ExternalAddress = localhostAddr + ":" + strconv.Itoa(int(o.consensusPort))

	if o.supplementarySanityInterval > 0 {
		o.Config.Consensus.SupplementarySanity.Enabled = true
		o.Config.Consensus.SupplementarySanity.Interval = o.supplementarySanityInterval
	}

	o.Config.P2P.Port = o.p2pPort

	if !o.entity.isDebugTestEntity {
		entityID, _ := o.entity.ID().MarshalText() // Cannot fail.
		o.Config.Registration.EntityID = string(entityID)
	}

	o.Config.Mode = config.ModeClient
	o.Config.Runtime.Provisioner = o.runtimeProvisioner
	o.Config.Runtime.SGX.Loader = o.net.cfg.RuntimeSGXLoaderBinary
	o.Config.Runtime.AttestInterval = o.net.cfg.RuntimeAttestInterval

	o.AddSeedNodesToConfig()

	return nil
}

// NewObserver provisions a new observer node and adds it to the network.
func (net *Network) NewObserver(cfg *ObserverCfg) (*Observer, error) {
	observerName := fmt.Sprintf("observer-%d", len(net.observers))
	host, err := net.GetNamedNode(observerName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	// Pre-provision the node identity so that we can identify the entity.
	err = host.setProvisionedIdentity(fmt.Sprintf(observerIdentitySeedTemplate, len(net.observers)))
	if err != nil {
		return nil, fmt.Errorf("oasis/observer: failed to provision node identity: %w", err)
	}

	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = runtimeConfig.RuntimeProvisionerSandboxed
	}

	observer := &Observer{
		Node:               host,
		runtimes:           cfg.Runtimes,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		runtimeConfig:      cfg.RuntimeConfig,
		consensusPort:      host.getProvisionedPort(nodePortConsensus),
		p2pPort:            host.getProvisionedPort(nodePortP2P),
	}

	// Remove any exploded bundles on cleanup.
	net.env.AddOnCleanup(func() {
		_ = os.RemoveAll(bundle.ExplodedPath(observer.dir.String()))
	})

	net.observers = append(net.observers, observer)
	host.features = append(host.features, observer)

	return observer, nil
}
