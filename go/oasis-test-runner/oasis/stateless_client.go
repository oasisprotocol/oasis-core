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
	statelessClientIdentitySeedTemplate = "ekiden node stateless client %d"
)

// StatelessClient is an Oasis stateless client node.
type StatelessClient struct {
	*Node

	consensusPort uint16
	p2pPort       uint16

	runtimes           []int
	runtimeConfig      map[int]map[string]any
	runtimeProvisioner runtimeConfig.RuntimeProvisioner
}

// StatelessClientCfg is the Oasis stateless client node provisioning configuration.
type StatelessClientCfg struct {
	NodeCfg

	Runtimes           []int
	RuntimeConfig      map[int]map[string]any
	RuntimeProvisioner runtimeConfig.RuntimeProvisioner
}

func (client *StatelessClient) AddArgs(args *argBuilder) error {
	args.appendNetwork(client.net)

	for _, idx := range client.runtimes {
		v := client.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		client.addHostedRuntime(v, client.runtimeConfig[idx])
	}

	return nil
}

func (client *StatelessClient) ModifyConfig() error {
	client.Config.Consensus.ListenAddress = allInterfacesAddr + ":" + strconv.Itoa(int(client.consensusPort))
	client.Config.Consensus.ExternalAddress = localhostAddr + ":" + strconv.Itoa(int(client.consensusPort))

	if client.supplementarySanityInterval > 0 {
		client.Config.Consensus.SupplementarySanity.Enabled = true
		client.Config.Consensus.SupplementarySanity.Interval = client.supplementarySanityInterval
	}

	client.Config.P2P.Port = client.p2pPort

	client.Config.Mode = config.ModeStatelessClient
	client.Config.Runtime.Provisioner = client.runtimeProvisioner
	client.Config.Runtime.SGX.Loader = client.net.cfg.RuntimeSGXLoaderBinary
	client.Config.Runtime.AttestInterval = client.net.cfg.RuntimeAttestInterval

	client.AddSeedNodesToConfig()

	return nil
}

// NewStatelessClient provisions a new stateless client node and adds it to the network.
func (net *Network) NewStatelessClient(cfg *StatelessClientCfg) (*StatelessClient, error) {
	clientName := fmt.Sprintf("client-stateless-%d", len(net.statelessClients))
	host, err := net.GetNamedNode(clientName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	// Pre-provision the node identity so that we can identify the entity.
	err = host.setProvisionedIdentity(fmt.Sprintf(statelessClientIdentitySeedTemplate, len(net.statelessClients)))
	if err != nil {
		return nil, fmt.Errorf("oasis/client-stateless: failed to provision node identity: %w", err)
	}

	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = runtimeConfig.RuntimeProvisionerSandboxed
	}

	client := &StatelessClient{
		Node:               host,
		runtimes:           cfg.Runtimes,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		runtimeConfig:      cfg.RuntimeConfig,
		consensusPort:      host.getProvisionedPort(nodePortConsensus),
		p2pPort:            host.getProvisionedPort(nodePortP2P),
	}

	// Remove any exploded bundles on cleanup.
	net.env.AddOnCleanup(func() {
		_ = os.RemoveAll(bundle.ExplodedPath(client.dir.String()))
	})

	net.statelessClients = append(net.statelessClients, client)
	host.features = append(host.features, client)

	return client, nil
}
