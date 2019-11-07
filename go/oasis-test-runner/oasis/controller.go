package oasis

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/grpc/client"
	"github.com/oasislabs/oasis-core/go/grpc/control"
	"github.com/oasislabs/oasis-core/go/grpc/dummydebug"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	stakingClient "github.com/oasislabs/oasis-core/go/staking/client"
)

type DebugController struct {
	debugClient dummydebug.DummyDebugClient
}

// WaitNodesRegistered waits for a given number of nodes to be
// registered in the registry.
func (c *DebugController) WaitNodesRegistered(ctx context.Context, count int) error {
	_, err := c.debugClient.WaitNodes(ctx, &dummydebug.WaitNodesRequest{Nodes: uint64(count)})
	return err
}

// SetEpoch sets the given epoch.
//
// Note that this will only work in case the mock epochtime backend
// is being used.
func (c *DebugController) SetEpoch(ctx context.Context, epoch uint64) error {
	_, err := c.debugClient.SetEpoch(ctx, &dummydebug.SetEpochRequest{Epoch: epoch})
	return err
}

type RuntimeClientController struct {
	rtClient client.RuntimeClient
}

// WaitEpoch waits for epoch to be reached.
func (c *RuntimeClientController) WaitEpoch(ctx context.Context, epoch uint64) error {
	_, err := c.rtClient.WaitEpoch(ctx, &client.WaitEpochRequest{Epoch: epoch})
	return err
}

type NodeController struct {
	ctrlClient control.ControlClient
}

// WaitReady waits for the node to be ready to process requests.
func (c *NodeController) WaitReady(ctx context.Context) error {
	// TODO: Use WaitReady when available (#2130).
	_, err := c.ctrlClient.WaitSync(ctx, &control.WaitSyncRequest{})
	return err
}

// Controller is a network controller that connects to one of the
// Oasis nodes and enables queries and issuing commands.
type Controller struct {
	DebugController
	RuntimeClientController
	NodeController

	Staking staking.Backend
}

// NewController creates a new node controller given the path to
// a node's internal socket.
func NewController(socketPath string) (*Controller, error) {
	conn, err := grpc.Dial(
		"unix:"+socketPath,
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	if err != nil {
		return nil, err
	}

	sc, err := stakingClient.New(conn)
	if err != nil {
		return nil, err
	}

	return &Controller{
		DebugController: DebugController{
			debugClient: dummydebug.NewDummyDebugClient(conn),
		},
		RuntimeClientController: RuntimeClientController{
			rtClient: client.NewRuntimeClient(conn),
		},
		NodeController: NodeController{
			ctrlClient: control.NewControlClient(conn),
		},
		Staking: sc,
	}, nil
}
