package oasis

import (
	"fmt"

	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

const (
	clientIdentitySeedTemplate = "ekiden node client %d"
)

// Client is an Oasis client node.
type Client struct {
	*Node

	runtimes           []int
	runtimeProvisioner string
	runtimeConfig      map[int]map[string]interface{}

	consensusPort uint16
	p2pPort       uint16
}

// ClientCfg is the Oasis client node provisioning configuration.
type ClientCfg struct {
	NodeCfg

	Runtimes           []int
	RuntimeProvisioner string
	RuntimeConfig      map[int]map[string]interface{}
}

func (client *Client) AddArgs(args *argBuilder) error {
	args.debugDontBlameOasis().
		debugAllowRoot().
		debugAllowTestKeys().
		debugSetRlimit().
		debugEnableProfiling(client.Node.pprofPort).
		runtimeProvisioner(client.runtimeProvisioner).
		tendermintPrune(client.consensus.PruneNumKept, client.consensus.PruneInterval).
		tendermintRecoverCorruptedWAL(client.consensus.TendermintRecoverCorruptedWAL).
		tendermintCoreAddress(client.consensusPort).
		appendNetwork(client.net).
		appendSeedNodes(client.net.seeds).
		workerP2pPort(client.p2pPort).
		tendermintSupplementarySanity(client.supplementarySanityInterval)

	if len(client.runtimes) > 0 {
		args.runtimeMode(runtimeRegistry.RuntimeModeClientStateless)
	}

	for _, idx := range client.runtimes {
		v := client.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		client.addHostedRuntime(v, client.runtimeConfig[idx])
	}

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
		cfg.RuntimeProvisioner = runtimeRegistry.RuntimeProvisionerSandboxed
	}
	if isNoSandbox() {
		cfg.RuntimeProvisioner = runtimeRegistry.RuntimeProvisionerUnconfined
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
