package oasis

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
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
	Consensus     consensus.Services
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
