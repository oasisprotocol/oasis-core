package oasis

import (
	"google.golang.org/grpc"

	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	control "github.com/oasislabs/oasis-core/go/control/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

// Controller is a network controller that connects to one of the
// Oasis nodes and enables queries and issuing commands.
type Controller struct {
	control.DebugController
	control.NodeController

	Consensus     consensus.ClientBackend
	Staking       staking.Backend
	Registry      registry.Backend
	RuntimeClient runtimeClient.RuntimeClient
	Storage       storage.Backend

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
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return nil, err
	}

	return &Controller{
		DebugController: control.NewDebugControllerClient(conn),
		NodeController:  control.NewNodeControllerClient(conn),
		Consensus:       consensus.NewConsensusClient(conn),
		Staking:         staking.NewStakingClient(conn),
		Registry:        registry.NewRegistryClient(conn),
		RuntimeClient:   runtimeClient.NewRuntimeClient(conn),
		Storage:         storage.NewStorageClient(conn),

		conn: conn,
	}, nil
}
