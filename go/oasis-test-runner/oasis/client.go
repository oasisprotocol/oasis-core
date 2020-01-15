package oasis

import (
	"fmt"

	"github.com/pkg/errors"

	registry "github.com/oasislabs/oasis-core/go/registry/api"
	storageClient "github.com/oasislabs/oasis-core/go/storage/client"
)

// Client is an Oasis client node.
type Client struct {
	Node

	consensusPort uint16
}

func (client *Client) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		tendermintCoreListenAddress(client.consensusPort).
		storageBackend(storageClient.BackendName).
		appendNetwork(client.net).
		runtimeTagIndexerBackend("bleve")
	for _, v := range client.net.runtimes {
		if v.kind != registry.KindCompute {
			continue
		}
		args = args.runtimeSupported(v.id).
			appendRuntimePruner(&v.pruner)
	}

	var err error
	if client.cmd, client.exitCh, err = client.net.startOasisNode(
		client.dir,
		nil,
		args,
		client.Name,
		false,
		false,
	); err != nil {
		return fmt.Errorf("oasis/client: failed to launch node %s: %w", client.Name, err)
	}

	return nil
}

// Start starts an Oasis node.
func (client *Client) Start() error {
	return client.startNode()
}

// NewClient provisions a new client node and adds it to the network.
func (net *Network) NewClient() (*Client, error) {
	clientName := fmt.Sprintf("client-%d", len(net.clients))

	clientDir, err := net.baseDir.NewSubDir(clientName)
	if err != nil {
		net.logger.Error("failed to create client subdir",
			"err", err,
			"client_name", clientName,
		)
		return nil, errors.Wrap(err, "oasis/client: failed to create client subdir")
	}

	client := &Client{
		Node: Node{
			Name: clientName,
			net:  net,
			dir:  clientDir,
		},
		consensusPort: net.nextNodePort,
	}
	client.doStartNode = client.startNode

	net.clients = append(net.clients, client)
	net.nextNodePort++

	return client, nil
}
