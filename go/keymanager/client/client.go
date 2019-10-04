// Package client implements the key manager client.
package client

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"sync"

	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/keymanager/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/worker/common/enclaverpc"
)

const (
	cfgDebugClientAddress = "keymanager.debug.client.address"
	cfgDebugClientCert    = "keymanager.debug.client.certificate"

	kmEndpoint = "key-manager"
)

var (
	ErrKeyManagerNotAvailable = errors.New("keymanager/client: key manager not available")

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

// Client is a key manager client instance.
type Client struct {
	sync.RWMutex

	logger *logging.Logger

	backend  api.Backend
	registry registry.Backend

	state map[signature.MapKey]*clientState
	kmMap map[signature.MapKey]signature.PublicKey

	debugClient *enclaverpc.Client
}

type clientState struct {
	status            *api.Status
	conn              *grpc.ClientConn
	client            *enclaverpc.Client
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

// CallRemote calls a runtime-specific key manager via remote EnclaveRPC.
func (c *Client) CallRemote(ctx context.Context, runtimeID signature.PublicKey, data []byte) ([]byte, error) {
	if c.debugClient != nil {
		return c.debugClient.CallEnclave(ctx, data)
	}

	c.logger.Debug("remote query",
		"id", runtimeID,
		"data", base64.StdEncoding.EncodeToString(data),
	)

	c.RLock()
	defer c.RUnlock()

	id := runtimeID.ToMapKey()
	kmID := c.kmMap[id]
	if kmID == nil {
		if c.state[id] == nil {
			return nil, ErrKeyManagerNotAvailable
		}

		// The target query is for a keymanager runtime ID, probably
		// replication.
		kmID = runtimeID
	}

	st := c.state[kmID.ToMapKey()]
	if st == nil || st.client == nil {
		return nil, ErrKeyManagerNotAvailable
	}

	return st.client.CallEnclave(ctx, data)
}

func (c *Client) worker() {
	stCh, stSub := c.backend.WatchStatuses()
	defer stSub.Close()

	rtCh, rtSub := c.registry.WatchRuntimes()
	defer rtSub.Close()

	nlCh, nlSub := c.registry.WatchNodeList()
	defer nlSub.Close()

	for {
		select {
		case st := <-stCh:
			nl, err := c.registry.GetNodes(context.TODO())
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
		c.logger.Debug("set new runtime key manager",
			"id", rt.ID,
			"km_id", rt.KeyManager,
		)
		c.kmMap[rt.ID.ToMapKey()] = rt.KeyManager
	case registry.KindKeyManager:
		c.kmMap[rt.ID.ToMapKey()] = rt.ID
	default:
	}
}

func (c *Client) updateState(status *api.Status, nodeList []*node.Node) {
	c.logger.Debug("updating connection state",
		"id", status.ID,
	)

	nodeMap := make(map[signature.MapKey]*node.Node)
	for _, n := range nodeList {
		nodeMap[n.ID.ToMapKey()] = n
	}

	c.Lock()
	defer c.Unlock()

	idKey := status.ID.ToMapKey()
	st := c.state[idKey]

	// It's not possible to service requests for this key manager.
	if !status.IsInitialized || len(status.Nodes) == 0 {
		// Kill the conn and return.
		if st != nil {
			st.kill()
			delete(c.state, idKey)
		}

		return
	}

	// Build the new state.
	certPool := x509.NewCertPool()
	var resolverState resolver.State
	for _, v := range status.Nodes {
		n := nodeMap[v.ToMapKey()]
		if n == nil {
			c.logger.Warn("key manager node missing descriptor",
				"id", v,
			)
			continue
		}

		cert, err := n.Committee.ParseCertificate()
		if err != nil {
			c.logger.Error("failed to parse key manager certificate",
				"id", n.ID,
				"err", err,
			)
			continue
		}
		certPool.AddCert(cert)

		for _, addr := range n.Committee.Addresses {
			resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
		}
	}

	creds := credentials.NewClientTLSFromCert(certPool, identity.CommonName)
	opts := grpc.WithTransportCredentials(creds)

	// TODO: This probably could skip updating the connection sometimes.

	// Kill the old state if it exists.
	if st != nil {
		st.kill()
		delete(c.state, idKey)
	}

	// Note: While this may look screwed up, the resolver needs the client conn
	// before populating addresses, dialing is defered till use, which can't
	// happen.
	manualResolver, address, cleanupFn := manual.NewManualResolver()
	conn, err := grpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name))
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

	c.state[idKey] = &clientState{
		status:            status,
		conn:              conn,
		client:            enclaverpc.NewFromConn(conn, kmEndpoint),
		resolverCleanupFn: cleanupFn,
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
func New(backend api.Backend, registryBackend registry.Backend) (*Client, error) {
	c := &Client{
		logger: logging.GetLogger("keymanager/client"),
		state:  make(map[signature.MapKey]*clientState),
		kmMap:  make(map[signature.MapKey]signature.PublicKey),
	}

	if debugAddress := viper.GetString(cfgDebugClientAddress); debugAddress != "" {
		debugCert := viper.GetString(cfgDebugClientCert)

		client, err := enclaverpc.NewClient(debugAddress, debugCert, kmEndpoint)
		if err != nil {
			return nil, errors.Wrap(err, "keymanager/client: failed to create debug client")
		}

		c.debugClient = client

		return c, nil
	}

	// Standard configuration watches the various backends.
	c.backend = backend
	c.registry = registryBackend

	go c.worker()

	return c, nil
}

func init() {
	Flags.String(cfgDebugClientAddress, "", "Key manager address")
	Flags.String(cfgDebugClientCert, "", "Key manager TLS certificate")

	_ = viper.BindPFlags(Flags)
}
