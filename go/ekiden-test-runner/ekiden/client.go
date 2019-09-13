package ekiden

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

// Client is an ekiden client node.
type Client struct {
	net *Network
	dir *env.Dir

	consensusPort uint16
}

// LogPath returns the path to the node's log.
func (client *Client) LogPath() string {
	return nodeLogPath(client.dir)
}

// SocketPath returns the path to the client's gRPC socket.
func (client *Client) SocketPath() string {
	return filepath.Join(client.dir.String(), internalSocketFile)
}

func (client *Client) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(client.consensusPort).
		roothashTendermintIndexBlocks().
		storageCachingclient(client.dir).
		appendNetwork(client.net)
	for _, v := range client.net.runtimes {
		args = args.clientIndexRuntimes(v.id)
	}

	if err := client.net.startEkidenNode(client.dir, nil, args, "client"); err != nil {
		return errors.Wrap(err, "ekiden/client: failed to launch node")
	}

	return nil
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
		return nil, errors.Wrap(err, "ekiden/client: failed to create client subdir")
	}

	client := &Client{
		net:           net,
		dir:           clientDir,
		consensusPort: net.nextNodePort,
	}

	net.clients = append(net.clients, client)
	net.nextNodePort++

	return client, nil
}
