package oasis

import (
	"google.golang.org/grpc"

	runtimeClient "github.com/oasislabs/oasis-core/go/client/api"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	control "github.com/oasislabs/oasis-core/go/control/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

// Controller is a network controller that connects to one of the
// Oasis nodes and enables queries and issuing commands.
type Controller struct {
	control.DebugController
	control.NodeController

	Staking       staking.Backend
	Consensus     consensus.ClientBackend
	RuntimeClient runtimeClient.RuntimeClient
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
		Staking:         staking.NewStakingClient(conn),
		Consensus:       consensus.NewConsensusClient(conn),
		RuntimeClient:   runtimeClient.NewRuntimeClient(conn),
	}, nil
}
