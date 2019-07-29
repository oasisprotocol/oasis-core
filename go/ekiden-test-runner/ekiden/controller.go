package ekiden

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/grpc/client"
	"github.com/oasislabs/ekiden/go/grpc/dummydebug"
)

// Controller is a network controller that connects to one of the
// Ekiden nodes and enables queries and issuing commands.
type Controller struct {
	debugClient dummydebug.DummyDebugClient
	rtClient    client.RuntimeClient
}

func (c *Controller) callOpts() []grpc.CallOption {
	return []grpc.CallOption{
		grpc.WaitForReady(true),
	}
}

// WaitNodesRegistered waits for a given number of nodes to be
// registered in the registry.
func (c *Controller) WaitNodesRegistered(ctx context.Context, count int) error {
	_, err := c.debugClient.WaitNodes(ctx, &dummydebug.WaitNodesRequest{Nodes: uint64(count)}, c.callOpts()...)
	return err
}

// SetEpoch sets the given epoch.
//
// Note that this will only work in case the mock epochtime backend
// is being used.
func (c *Controller) SetEpoch(ctx context.Context, epoch uint64) error {
	_, err := c.debugClient.SetEpoch(ctx, &dummydebug.SetEpochRequest{Epoch: epoch}, c.callOpts()...)
	return err
}

// WaitReady waits for the node to be ready to process requests.
func (c *Controller) WaitReady(ctx context.Context) error {
	// TODO: Use WaitReady when available (#2130).
	_, err := c.rtClient.WaitSync(ctx, &client.WaitSyncRequest{}, c.callOpts()...)
	return err
}

// NewController creates a new node controller given the path to
// a node's internal socket.
func NewController(socketPath string) (*Controller, error) {
	conn, err := grpc.Dial("unix:"+socketPath, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	return &Controller{
		debugClient: dummydebug.NewDummyDebugClient(conn),
		rtClient:    client.NewRuntimeClient(conn),
	}, nil
}
