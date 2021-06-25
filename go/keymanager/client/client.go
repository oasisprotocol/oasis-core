// Package client implements the key manager client.
package client

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes/grpc"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
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

	consensus consensus.Backend

	ctx         context.Context
	initCh      chan struct{}
	initialized bool

	committeeWatcher nodes.VersionedNodeDescriptorWatcher
	committeeClient  grpc.NodesClient

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

	var resp []byte
	call := func() error {
		conn := c.committeeClient.GetConnection()
		if conn == nil {
			c.logger.Warn("no key manager connection for runtime")
			return ErrKeyManagerNotAvailable
		}
		enclaveClient := enclaverpc.NewTransportClient(conn)

		var err error
		resp, err = enclaveClient.CallEnclave(ctx, &enclaverpc.CallEnclaveRequest{
			RuntimeID: c.runtime.ID(),
			Endpoint:  api.EnclaveRPCEndpoint,
			Payload:   data,
		})
		switch {
		case err == nil:
		case status.Code(err) == codes.PermissionDenied:
			// Calls can fail around epoch transitions, as the access policy
			// is being updated, so we must retry.
			return err
		case status.Code(err) == codes.Unavailable:
			// XXX: HACK: Find a better way to determine the root cause.
			switch {
			case strings.Contains(err.Error(), "tls: bad public key"):
				// Retry as the access policy could be in the process of being updated.
				return err
			case strings.Contains(err.Error(), "last resolver error: produced zero addresses"):
				// Retry as the connection may be in the process of being updated.
				return err
			default:
			}

			fallthrough
		default:
			// Request failed, communicate that to the node selection policy.
			c.committeeClient.UpdateNodeSelectionPolicy(grpc.NodeSelectionFeedback{Bad: err})
			return backoff.Permanent(err)
		}
		return nil
	}

	retry := backoff.WithMaxRetries(backoff.NewConstantBackOff(retryInterval), maxRetries)
	err := backoff.Retry(call, backoff.WithContext(retry, ctx))

	return resp, err
}

func (c *Client) worker() {
	stCh, stSub := c.consensus.KeyManager().WatchStatuses()
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
				if rt.Kind != registry.KindKeyManager {
					c.logger.Warn("runtime indicates no key manager is needed")
					continue
				}

				// We're a key manager client, that's interested in other
				// instances of ourself.
				kmID = &rt.ID
			}

			// Fetch current key manager status.
			st, err := c.consensus.KeyManager().GetStatus(c.ctx, &registry.NamespaceQuery{
				ID:     *kmID,
				Height: consensus.HeightLatest,
			})
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

	c.committeeWatcher.Reset()
	defer c.committeeWatcher.Freeze(0)

	// It's not possible to service requests for this key manager.
	if !status.IsInitialized || len(status.Nodes) == 0 {
		c.logger.Warn("key manager not initialized or has no nodes",
			"id", status.ID,
			"status", status,
		)
		return
	}

	for _, nodeID := range status.Nodes {
		_, err := c.committeeWatcher.WatchNode(c.ctx, nodeID)
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
	consensus consensus.Backend,
	identity *identity.Identity,
) (*Client, error) {
	committeeNodes, err := nodes.NewVersionedNodeDescriptorWatcher(ctx, consensus)
	if err != nil {
		return nil, fmt.Errorf("keymanager/client: failed to create node descriptor watcher: %w", err)
	}

	var opts []grpc.Option
	if identity != nil {
		opts = append(opts, grpc.WithClientAuthentication(identity))
	}
	committeeClient, err := grpc.NewNodesClient(ctx, committeeNodes, opts...)
	if err != nil {
		return nil, fmt.Errorf("keymanager/client: failed to create committee client: %w", err)
	}

	c := &Client{
		runtime:          runtime,
		consensus:        consensus,
		ctx:              ctx,
		initCh:           make(chan struct{}),
		committeeWatcher: committeeNodes,
		committeeClient:  committeeClient,
		logger: logging.GetLogger("keymanager/client").
			With("runtime_id", runtime.ID()),
	}
	go c.worker()

	return c, nil
}
