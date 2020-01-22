// Package client implements the key manager client.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/grpc/resolver/manual"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/keymanager/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	enclaverpc "github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
)

const (
	retryInterval = 1 * time.Second
	maxRetries    = 15
)

// ErrKeyManagerNotAvailable is the error when a key manager is not available.
var ErrKeyManagerNotAvailable = errors.New("keymanager/client: key manager not available")

// TODO: Consider making the key manager client per-runtime instead of it tracking all runtimes.

// Client is a key manager client instance.
type Client struct {
	sync.RWMutex

	logger *logging.Logger

	nodeIdentity *identity.Identity

	backend  api.Backend
	registry registry.Backend

	state map[common.Namespace]*clientState
	kmMap map[common.Namespace]common.Namespace

	readyNotifier *pubsub.Broker
}

type clientState struct {
	status            *api.Status
	conn              *grpc.ClientConn
	client            enclaverpc.Transport
	resolverCleanupFn func()
}

func (st *clientState) kill() {
	if st.resolverCleanupFn != nil {
		st.resolverCleanupFn()
		st.resolverCleanupFn = nil
	}
	if st.conn != nil {
		st.conn.Close()
		st.conn = nil
	}
}

// WaitReady waits for the key manager for the specific runtime to become ready.
func (c *Client) WaitReady(ctx context.Context, runtimeID common.Namespace) error {
	sub := func() *pubsub.Subscription {
		c.RLock()
		defer c.RUnlock()

		if kmID, ok := c.kmMap[runtimeID]; ok && c.state[kmID] != nil {
			return nil
		}

		return c.readyNotifier.Subscribe()
	}()
	if sub == nil {
		return nil
	}
	defer sub.Close()

	typedCh := make(chan common.Namespace)
	sub.Unwrap(typedCh)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case rtID := <-typedCh:
			if !rtID.Equal(&runtimeID) {
				continue
			}

			return nil
		}
	}
}

// CallRemote calls a runtime-specific key manager via remote EnclaveRPC.
func (c *Client) CallRemote(ctx context.Context, runtimeID common.Namespace, data []byte) ([]byte, error) {
	c.logger.Debug("remote query",
		"id", runtimeID,
		"data", base64.StdEncoding.EncodeToString(data),
	)

	c.RLock()
	defer c.RUnlock()

	kmID, ok := c.kmMap[runtimeID]
	if !ok {
		c.logger.Error("no known key manager for runtime",
			"id", runtimeID,
		)
		return nil, ErrKeyManagerNotAvailable
	}

	st := c.state[kmID]
	if st == nil || st.client == nil {
		c.logger.Error("no key manager connection for runtime",
			"id", runtimeID,
			"km_id", kmID,
		)
		return nil, ErrKeyManagerNotAvailable
	}

	var (
		resp       []byte
		numRetries int
	)
	call := func() error {
		var err error
		resp, err = st.client.CallEnclave(ctx, &enclaverpc.CallEnclaveRequest{
			RuntimeID: runtimeID,
			Endpoint:  api.EnclaveRPCEndpoint,
			Payload:   data,
		})
		if status.Code(err) == codes.PermissionDenied && numRetries < maxRetries {
			// Calls can fail around epoch transitions, as the access policy
			// is being updated, so we must retry (up to maxRetries).
			numRetries++
			return err
		}
		return backoff.Permanent(err)
	}

	retry := backoff.NewConstantBackOff(retryInterval)
	err := backoff.Retry(call, backoff.WithContext(retry, ctx))

	return resp, err
}

func (c *Client) worker() {
	ctx := context.TODO()

	stCh, stSub := c.backend.WatchStatuses()
	defer stSub.Close()

	rtCh, rtSub, err := c.registry.WatchRuntimes(ctx)
	if err != nil {
		c.logger.Error("failed to watch runtimes",
			"err", err,
		)
		panic("failed to watch runtimes")
	}
	defer rtSub.Close()

	nlCh, nlSub, err := c.registry.WatchNodeList(ctx)
	if err != nil {
		c.logger.Error("failed to watch node lists",
			"err", err,
		)
		panic("failed to watch node lists")
	}
	defer nlSub.Close()

	for {
		select {
		case st := <-stCh:
			nl, err := c.registry.GetNodes(ctx, consensus.HeightLatest)
			if err != nil {
				c.logger.Error("failed to poll node list",
					"err", err,
				)
				continue
			}
			c.updateState(st, nl)
		case rt := <-rtCh:
			c.updateRuntime(rt)
		case nl := <-nlCh:
			c.updateNodes(nl.Nodes)
		}
	}
}

func (c *Client) updateRuntime(rt *registry.Runtime) {
	c.Lock()
	defer c.Unlock()

	switch rt.Kind {
	case registry.KindCompute:
		if rt.KeyManager != nil {
			c.kmMap[rt.ID] = *rt.KeyManager

			// Notify subscribers if a key manager is now available.
			if st := c.state[*rt.KeyManager]; st != nil {
				c.readyNotifier.Broadcast(rt.ID)
			}
		}
		c.logger.Debug("set new runtime key manager",
			"id", rt.ID,
			"km_id", rt.KeyManager,
		)
	case registry.KindKeyManager:
		c.kmMap[rt.ID] = rt.ID
	default:
	}
}

func (c *Client) updateState(status *api.Status, nodeList []*node.Node) {
	c.logger.Debug("updating connection state",
		"id", status.ID,
	)

	nodeMap := make(map[signature.PublicKey]*node.Node)
	for _, n := range nodeList {
		nodeMap[n.ID] = n
	}

	c.Lock()
	defer c.Unlock()

	st := c.state[status.ID]

	// It's not possible to service requests for this key manager.
	if !status.IsInitialized || len(status.Nodes) == 0 {
		c.logger.Warn("key manager not initialized or has no nodes",
			"id", status.ID,
			"status", status,
		)

		// Kill the conn and return.
		if st != nil {
			st.kill()
			delete(c.state, status.ID)
		}

		return
	}

	// Build the new state.
	certPool := x509.NewCertPool()
	var resolverState resolver.State
	for _, v := range status.Nodes {
		n := nodeMap[v]
		if n == nil {
			c.logger.Warn("key manager node missing descriptor",
				"id", v,
			)
			continue
		}

		for _, addr := range n.Committee.Addresses {
			nodeCert, err := addr.ParseCertificate()
			if err != nil {
				c.logger.Error("failed to parse key manager certificate",
					"id", n.ID,
					"err", err,
				)
				continue
			}
			certPool.AddCert(nodeCert)
		}

		for _, addr := range n.Committee.Addresses {
			resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
		}
	}

	// Open a gRPC connection using the node's TLS certificate.
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{*c.nodeIdentity.TLSCertificate},
		RootCAs:      certPool,
		ServerName:   identity.CommonName,
	})
	opts := grpc.WithTransportCredentials(creds)

	// TODO: This probably could skip updating the connection sometimes.

	// Kill the old state if it exists.
	if st != nil {
		st.kill()
		delete(c.state, status.ID)
	}

	// Note: While this may look screwed up, the resolver needs the client conn
	// before populating addresses, dialing is defered till use, which can't
	// happen.
	manualResolver, address, cleanupFn := manual.NewManualResolver()
	conn, err := cmnGrpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name)) //nolint: staticcheck
	if err != nil {
		cleanupFn()
		c.logger.Error("failed to create new gRPC client",
			"err", err,
		)
		return
	}
	manualResolver.UpdateState(resolverState)

	c.logger.Debug("updated connection",
		"id", status.ID,
	)

	c.state[status.ID] = &clientState{
		status:            status,
		conn:              conn,
		client:            enclaverpc.NewTransportClient(api.Service, conn),
		resolverCleanupFn: cleanupFn,
	}

	for k, v := range c.kmMap {
		if v.Equal(&status.ID) {
			c.readyNotifier.Broadcast(k)
		}
	}
}

func (c *Client) updateNodes(nodeList []*node.Node) {
	var statuses []*api.Status

	// This is ok because the caller's leaf functions are the only thing
	// that mutates the status list.
	c.RLock()
	for _, v := range c.state {
		statuses = append(statuses, v.status)
	}
	c.RUnlock()

	for _, v := range statuses {
		c.updateState(v, nodeList)
	}
}

// New creates a new key manager client instance.
func New(backend api.Backend, registryBackend registry.Backend, nodeIdentity *identity.Identity) (*Client, error) {
	c := &Client{
		logger:        logging.GetLogger("keymanager/client"),
		nodeIdentity:  nodeIdentity,
		state:         make(map[common.Namespace]*clientState),
		kmMap:         make(map[common.Namespace]common.Namespace),
		backend:       backend,
		registry:      registryBackend,
		readyNotifier: pubsub.NewBroker(false),
	}
	go c.worker()

	return c, nil
}
