package oasis

import (
	"fmt"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/config"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
)

const (
	clientIdentitySeedTemplate = "ekiden node client %d"
)

// Client is an Oasis client node.
type Client struct {
	*Node

	runtimes           []int
	runtimeProvisioner runtimeConfig.RuntimeProvisioner
	runtimeConfig      map[int]map[string]interface{}

	consensusPort uint16
	p2pPort       uint16
}

// ClientCfg is the Oasis client node provisioning configuration.
type ClientCfg struct {
	NodeCfg

	Runtimes           []int
	RuntimeProvisioner runtimeConfig.RuntimeProvisioner
	RuntimeConfig      map[int]map[string]interface{}
}

func (client *Client) AddArgs(args *argBuilder) error {
	args.appendNetwork(client.net)

	for _, idx := range client.runtimes {
		v := client.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		client.addHostedRuntime(v, client.runtimeConfig[idx])
	}

	return nil
}

func (client *Client) ModifyConfig() error {
	client.Config.Consensus.ListenAddress = "tcp://0.0.0.0:" + strconv.Itoa(int(client.consensusPort))
	client.Config.Consensus.ExternalAddress = "tcp://127.0.0.1:" + strconv.Itoa(int(client.consensusPort))

	if client.supplementarySanityInterval > 0 {
		client.Config.Consensus.SupplementarySanity.Enabled = true
		client.Config.Consensus.SupplementarySanity.Interval = client.supplementarySanityInterval
	}

	client.Config.P2P.Port = client.p2pPort

	if len(client.runtimes) > 0 {
		client.Config.Mode = config.ModeStatelessClient
		client.Config.Runtime.Provisioner = client.runtimeProvisioner
	}

	client.AddSeedNodesToConfig()

	return nil
}

// NewClient provisions a new client node and adds it to the network.
func (net *Network) NewClient(cfg *ClientCfg) (*Client, error) {
	clientName := fmt.Sprintf("client-%d", len(net.clients))
	host, err := net.GetNamedNode(clientName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = runtimeConfig.RuntimeProvisionerSandboxed
	}

	// Pre-provision the node identity so that we can identify the entity.
	err = host.setProvisionedIdentity(false, fmt.Sprintf(clientIdentitySeedTemplate, len(net.clients)))
	if err != nil {
		return nil, fmt.Errorf("oasis/client: failed to provision node identity: %w", err)
	}

	client := &Client{
		Node:               host,
		runtimes:           cfg.Runtimes,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		runtimeConfig:      cfg.RuntimeConfig,
		consensusPort:      host.getProvisionedPort(nodePortConsensus),
		p2pPort:            host.getProvisionedPort(nodePortP2P),
	}

	net.clients = append(net.clients, client)
	host.features = append(host.features, client)

	return client, nil
}
