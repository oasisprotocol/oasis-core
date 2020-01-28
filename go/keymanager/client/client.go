// Package client implements the key manager client.
package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/runtime/committee"
	enclaverpc "github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
)

const (
	retryInterval = 1 * time.Second
	maxRetries    = 15
)

// ErrKeyManagerNotAvailable is the error when a key manager is not available.
var ErrKeyManagerNotAvailable = errors.New("keymanager/client: key manager not available")

// Client is a key manager client instance.
type Client struct {
	runtime runtimeRegistry.Runtime

	backend  api.Backend
	registry registry.Backend

	ctx         context.Context
	initCh      chan struct{}
	initialized bool

	committeeNodes  committee.NodeDescriptorWatcher
	committeeClient committee.Client

	logger *logging.Logger
}

// Initialized returns a channel that is closed when the key manager client is initialized.
func (c *Client) Initialized() <-chan struct{} {
	return c.initCh
}

// CallRemote calls the key manager via remote EnclaveRPC.
func (c *Client) CallRemote(ctx context.Context, data []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.initCh:
	}

	c.logger.Debug("remote query",
		"data", base64.StdEncoding.EncodeToString(data),
	)

	var (
		resp       []byte
		numRetries int
	)
	call := func() error {
		conn := c.committeeClient.GetConnection()
		if conn == nil {
			c.logger.Error("no key manager connection for runtime")
			return backoff.Permanent(ErrKeyManagerNotAvailable)
		}
		client := enclaverpc.NewTransportClient(api.Service, conn)

		var err error
		resp, err = client.CallEnclave(ctx, &enclaverpc.CallEnclaveRequest{
			RuntimeID: c.runtime.ID(),
			Endpoint:  api.EnclaveRPCEndpoint,
			Payload:   data,
		})
		if status.Code(err) == codes.PermissionDenied && numRetries < maxRetries {
			// Calls can fail around epoch transitions, as the access policy
			// is being updated, so we must retry (up to maxRetries).
			numRetries++
			return err
		}
		// Request failed, communicate that to the node selection policy.
		c.committeeClient.UpdateNodeSelectionPolicy(committee.NodeSelectionFeedback{Bad: err})
		return backoff.Permanent(err)
	}

	retry := backoff.NewConstantBackOff(retryInterval)
	err := backoff.Retry(call, backoff.WithContext(retry, ctx))

	return resp, err
}

func (c *Client) worker() {
	stCh, stSub := c.backend.WatchStatuses()
	defer stSub.Close()

	rtCh, rtSub, err := c.runtime.WatchRegistryDescriptor()
	if err != nil {
		c.logger.Error("failed to watch runtimes",
			"err", err,
		)
		panic("failed to watch runtimes")
	}
	defer rtSub.Close()

	var kmID *common.Namespace
	for {
		select {
		case <-c.ctx.Done():
			return
		case st := <-stCh:
			// Ignore status updates if key manager is not yet known (is nil) or if the status
			// update is for a different key manager.
			if !st.ID.Equal(kmID) {
				continue
			}

			c.updateState(st)
		case rt := <-rtCh:
			kmID = rt.KeyManager
			if kmID == nil {
				c.logger.Warn("runtime indicates no key manager is needed")
				continue
			}

			// Fetch current key manager status.
			st, err := c.backend.GetStatus(c.ctx, *rt.KeyManager, consensus.HeightLatest)
			if err != nil {
				c.logger.Warn("failed to get key manager status",
					"err", err,
				)
				continue
			}

			c.updateState(st)
		}
	}
}

func (c *Client) updateState(status *api.Status) {
	c.logger.Debug("updating connection state",
		"id", status.ID,
	)

	c.committeeNodes.Reset()
	defer c.committeeNodes.Freeze(0)

	// It's not possible to service requests for this key manager.
	if !status.IsInitialized || len(status.Nodes) == 0 {
		c.logger.Warn("key manager not initialized or has no nodes",
			"id", status.ID,
			"status", status,
		)
		return
	}

	for _, nodeID := range status.Nodes {
		_, err := c.committeeNodes.WatchNode(c.ctx, nodeID)
		if err != nil {
			c.logger.Warn("failed to watch node",
				"err", err,
			)
			continue
		}
	}

	if !c.initialized {
		close(c.initCh)
		c.initialized = true
	}
}

// New creates a new key manager client instance.
func New(
	ctx context.Context,
	runtime runtimeRegistry.Runtime,
	backend api.Backend,
	registry registry.Backend,
	identity *identity.Identity,
) (*Client, error) {
	committeeNodes, err := committee.NewNodeDescriptorWatcher(ctx, registry)
	if err != nil {
		return nil, fmt.Errorf("keymanager/client: failed to create node descriptor watcher: %w", err)
	}

	var opts []committee.ClientOption
	if identity != nil {
		opts = append(opts, committee.WithClientAuthentication(identity))
	}
	committeeClient, err := committee.NewClient(ctx, committeeNodes, opts...)
	if err != nil {
		return nil, fmt.Errorf("keymanager/client: failed to create committee client: %w", err)
	}

	c := &Client{
		runtime:         runtime,
		backend:         backend,
		registry:        registry,
		ctx:             ctx,
		initCh:          make(chan struct{}),
		committeeNodes:  committeeNodes,
		committeeClient: committeeClient,
		logger:          logging.GetLogger("keymanager/client").With("runtime_id", runtime.ID()),
	}
	go c.worker()

	return c, nil
}
