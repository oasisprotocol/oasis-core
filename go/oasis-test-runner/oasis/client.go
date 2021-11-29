package oasis

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

// Client is an Oasis client node.
type Client struct {
	*Node

	runtimes           []int
	runtimeProvisioner string
	runtimeConfig      map[int]map[string]interface{}
	maxTransactionAge  int64

	consensusPort uint16
	p2pPort       uint16
}

// ClientCfg is the Oasis client node provisioning configuration.
type ClientCfg struct {
	NodeCfg

	Runtimes           []int
	RuntimeProvisioner string
	RuntimeConfig      map[int]map[string]interface{}
	MaxTransactionAge  int64
}

func (client *Client) AddArgs(args *argBuilder) error {
	args.debugDontBlameOasis().
		debugAllowTestKeys().
		debugSetRlimit().
		debugEnableProfiling(client.Node.pprofPort).
		runtimeMode(runtimeRegistry.RuntimeModeClientStateless).
		runtimeProvisioner(client.runtimeProvisioner).
		tendermintPrune(client.consensus.PruneNumKept).
		tendermintRecoverCorruptedWAL(client.consensus.TendermintRecoverCorruptedWAL).
		tendermintCoreAddress(client.consensusPort).
		appendNetwork(client.net).
		appendSeedNodes(client.net.seeds).
		workerP2pPort(client.p2pPort).
		tendermintSupplementarySanity(client.supplementarySanityInterval)

	if client.maxTransactionAge != 0 {
		args.runtimeClientMaxTransactionAge(client.maxTransactionAge)
	}

	for _, idx := range client.runtimes {
		v := client.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		client.addHostedRuntime(v, node.TEEHardwareInvalid, 0, client.runtimeConfig[idx])
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

	client := &Client{
		Node:               host,
		runtimes:           cfg.Runtimes,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		runtimeConfig:      cfg.RuntimeConfig,
		maxTransactionAge:  cfg.MaxTransactionAge,
		consensusPort:      host.getProvisionedPort(nodePortConsensus),
		p2pPort:            host.getProvisionedPort(nodePortP2P),
	}

	net.clients = append(net.clients, client)
	host.features = append(host.features, client)

	return client, nil
}
