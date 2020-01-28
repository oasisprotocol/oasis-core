package client

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/runtime/committee"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

// BackendName is the name of this implementation.
const BackendName = "client"

func newClient(
	ctx context.Context,
	namespace common.Namespace,
	ident *identity.Identity,
	nodes committee.NodeDescriptorLookup,
) (api.Backend, error) {
	committeeClient, err := committee.NewClient(ctx, nodes, committee.WithClientAuthentication(ident))
	if err != nil {
		return nil, fmt.Errorf("storage/client: failed to create committee client: %w", err)
	}

	b := &storageClientBackend{
		ctx:             ctx,
		logger:          logging.GetLogger("storage/client"),
		committeeClient: committeeClient,
	}
	return b, nil
}

// New creates a new storage client that automatically follows a given runtime's storage committee.
func New(
	ctx context.Context,
	namespace common.Namespace,
	ident *identity.Identity,
	schedulerBackend scheduler.Backend,
	registryBackend registry.Backend,
) (api.Backend, error) {
	committeeWatcher, err := committee.NewWatcher(
		ctx,
		schedulerBackend,
		registryBackend,
		namespace,
		scheduler.KindStorage,
		committee.WithAutomaticEpochTransitions(),
	)
	if err != nil {
		return nil, fmt.Errorf("storage/client: failed to create committee watcher: %w", err)
	}

	return newClient(ctx, namespace, ident, committeeWatcher.Nodes())
}

// NewStatic creates a new storage client that only follows a specific storage node. This is mostly
// useful for tests.
func NewStatic(
	ctx context.Context,
	namespace common.Namespace,
	ident *identity.Identity,
	registryBackend registry.Backend,
	nodeID signature.PublicKey,
) (api.Backend, error) {
	nw, err := committee.NewNodeDescriptorWatcher(ctx, registryBackend)
	if err != nil {
		return nil, fmt.Errorf("storage/client: failed to create node descriptor watcher: %w", err)
	}

	client, err := newClient(ctx, namespace, ident, nw)
	if err != nil {
		return nil, err
	}

	nw.Reset()
	_, err = nw.WatchNode(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("storage/client: failed to watch node %s: %w", nodeID, err)
	}
	nw.Freeze(0)

	return client, nil
}
