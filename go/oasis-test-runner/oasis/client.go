package oasis

import (
	"fmt"

	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// Client is an Oasis client node.
type Client struct {
	Node

	maxTransactionAge int64

	consensusPort uint16
	p2pPort       uint16
}

// ClientCfg is the Oasis client node provisioning configuration.
type ClientCfg struct {
	NodeCfg

	MaxTransactionAge int64
}

func (client *Client) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		tendermintDebugDisableCheckTx(client.consensus.DisableCheckTx).
		tendermintPrune(client.consensus.PruneNumKept).
		tendermintRecoverCorruptedWAL(client.consensus.TendermintRecoverCorruptedWAL).
		tendermintCoreAddress(client.consensusPort).
		appendNetwork(client.net).
		appendSeedNodes(client.net.seeds).
		workerP2pPort(client.p2pPort).
		workerP2pEnabled().
		runtimeTagIndexerBackend("bleve")

	if client.maxTransactionAge != 0 {
		args = args.runtimeClientMaxTransactionAge(client.maxTransactionAge)
	}

	for _, v := range client.net.runtimes {
		if v.kind != registry.KindCompute {
			continue
		}
		args = args.runtimeSupported(v.id).
			appendRuntimePruner(&v.pruner)
	}

	if err := client.net.startOasisNode(&client.Node, nil, args); err != nil {
		return fmt.Errorf("oasis/client: failed to launch node %s: %w", client.Name, err)
	}

	return nil
}

// Start starts an Oasis node.
func (client *Client) Start() error {
	return client.startNode()
}

// NewClient provisions a new client node and adds it to the network.
func (net *Network) NewClient(cfg *ClientCfg) (*Client, error) {
	clientName := fmt.Sprintf("client-%d", len(net.clients))

	clientDir, err := net.baseDir.NewSubDir(clientName)
	if err != nil {
		net.logger.Error("failed to create client subdir",
			"err", err,
			"client_name", clientName,
		)
		return nil, fmt.Errorf("oasis/client: failed to create client subdir: %w", err)
	}

	client := &Client{
		Node: Node{
			Name:      clientName,
			net:       net,
			dir:       clientDir,
			consensus: cfg.Consensus,
		},
		maxTransactionAge: cfg.MaxTransactionAge,
		consensusPort:     net.nextNodePort,
		p2pPort:           net.nextNodePort + 1,
	}
	client.doStartNode = client.startNode

	net.clients = append(net.clients, client)
	net.nextNodePort += 2

	return client, nil
}
