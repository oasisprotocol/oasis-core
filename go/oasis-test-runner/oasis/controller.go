package oasis

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
)

// Controller is a network controller that connects to one of the
// Oasis nodes and enables queries and issuing commands.
type Controller struct {
	control.DebugController
	control.NodeController

	Beacon        beacon.Backend
	Consensus     consensus.Backend
	Staking       staking.Backend
	Governance    governance.Backend
	Registry      registry.Backend
	Roothash      roothash.Backend
	RuntimeClient runtime.RuntimeClient
	Storage       storage.Backend
	Keymanager    keymanager.Backend
	Vault         vault.Backend

	StorageWorker workerStorage.StorageWorker

	conn *grpc.ClientConn
}

// Close closes the gRPC connection with the node the controller is controlling.
func (c *Controller) Close() {
	c.conn.Close()
}

// WaitConsensusHeight waits until the controller observes at least specified consensus height.
func (c *Controller) WaitConsensusHeight(ctx context.Context, height int64) error {
	blkCh, sub, err := c.Consensus.WatchBlocks(ctx)
	if err != nil {
		return fmt.Errorf("failed to watch consensus blocks: %w", err)
	}
	defer sub.Close()

	for {
		select {
		case blk, ok := <-blkCh:
			if !ok {
				return fmt.Errorf("consensus block channel closed")
			}
			if blk.Height >= height {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// WaitRuntimeRound waits until the controller observes at least specified runtime round.
func (c *Controller) WaitRuntimeRound(ctx context.Context, runtimeID common.Namespace, round uint64) error {
	blkCh, sub, err := c.RuntimeClient.WatchBlocks(ctx, runtimeID)
	if err != nil {
		return fmt.Errorf("failed to watch runtime blocks: %w", err)
	}
	defer sub.Close()

	for {
		select {
		case annBlk, ok := <-blkCh:
			if !ok {
				return fmt.Errorf("runtime block channel closed")
			}
			if annBlk.Block.Header.Round >= round {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// NewController creates a new node controller given the path to
// a node's internal socket.
func NewController(socketPath string) (*Controller, error) {
	conn, err := cmnGrpc.Dial(
		"unix:"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return nil, err
	}

	return &Controller{
		DebugController: control.NewDebugControllerClient(conn),
		NodeController:  control.NewNodeControllerClient(conn),
		Beacon:          beacon.NewClient(conn),
		Consensus:       consensus.NewClient(conn),
		Staking:         staking.NewClient(conn),
		Governance:      governance.NewClient(conn),
		Registry:        registry.NewClient(conn),
		Roothash:        roothash.NewClient(conn),
		RuntimeClient:   runtime.NewClient(conn),
		Storage:         storage.NewClient(conn),
		Keymanager:      keymanager.NewClient(conn),
		Vault:           vault.NewClient(conn),

		StorageWorker: workerStorage.NewClient(conn),

		conn: conn,
	}, nil
}
