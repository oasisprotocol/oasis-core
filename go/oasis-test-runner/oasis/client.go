package oasis

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/node"
)

// Client is an Oasis client node.
type Client struct {
	*Node

	runtimes          []int
	maxTransactionAge int64

	consensusPort uint16
	p2pPort       uint16
}

// ClientCfg is the Oasis client node provisioning configuration.
type ClientCfg struct {
	NodeCfg

	Runtimes          []int
	MaxTransactionAge int64
}

func (client *Client) AddArgs(args *argBuilder) error {
	args.debugDontBlameOasis().
		debugAllowTestKeys().
		debugEnableProfiling(client.Node.pprofPort).
		tendermintPrune(client.consensus.PruneNumKept).
		tendermintRecoverCorruptedWAL(client.consensus.TendermintRecoverCorruptedWAL).
		tendermintCoreAddress(client.consensusPort).
		appendNetwork(client.net).
		appendSeedNodes(client.net.seeds).
		workerP2pPort(client.p2pPort).
		workerP2pEnabled().
		tendermintSupplementarySanity(client.supplementarySanityInterval)

	if client.maxTransactionAge != 0 {
		args.runtimeClientMaxTransactionAge(client.maxTransactionAge)
	}

	if len(client.runtimes) > 0 {
		args.runtimeTagIndexerBackend("bleve")
	}
	for _, idx := range client.runtimes {
		v := client.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		client.addHostedRuntime(v, node.TEEHardwareInvalid, 0)
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

	client := &Client{
		Node:              host,
		runtimes:          cfg.Runtimes,
		maxTransactionAge: cfg.MaxTransactionAge,
		consensusPort:     host.getProvisionedPort(nodePortConsensus),
		p2pPort:           host.getProvisionedPort(nodePortP2P),
	}

	net.clients = append(net.clients, client)
	host.features = append(host.features, client)

	return client, nil
}
