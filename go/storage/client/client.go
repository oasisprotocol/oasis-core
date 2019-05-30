// Package client implements a client for an ekiden storage node.
// Client obtains storage info by following scheduler committees.
// Note: client assumes committees for all runtimes share the same
// storage committee. Although client does follow per epoch storage
// committee changes, this is not exposed and client will always
// connect to the most recently scheduled storage node it knows
// about.
package client

import (
	"context"
	"crypto/x509"
	"io"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/grpc/storage"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	urkelDb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "client"

	// Address to connect to with the storage client.
	cfgDebugClientAddress = "storage.debug.client.address"

	// Path to certificate file for grpc
	cfgDebugClientTLSCertFile = "storage.debug.client.tls"
)

var (
	_ api.Backend = (*storageClientBackend)(nil)
)

// ErrStorageNotAvailable is the error returned when a storage is not
// available.
var ErrStorageNotAvailable = errors.New("storage client: storage not available")

type storageClientBackend struct {
	logger *logging.Logger

	timeSource epochtime.Backend
	scheduler  scheduler.Backend
	registry   registry.Backend

	state           *storageClientBackendState
	connectionState *storageClientConnectionState

	haltCtx      context.Context
	cancelFn     context.CancelFunc
	initCh       chan struct{}
	signaledInit bool
}

// storageClientConnectionState contains the latest scheduled
// storage client and connection.
type storageClientConnectionState struct {
	sync.RWMutex

	client            storage.StorageClient
	conn              *grpc.ClientConn
	resolverCleanupCb func()
	node              *node.Node
}

// storageClientBackendState contains the most recent epoch information,
// and per epoch registry node lists and scheduler storage committees
type storageClientBackendState struct {
	sync.RWMutex

	logger *logging.Logger

	storageNodeList      map[epochtime.EpochTime][]*node.Node
	storageNodeLeaderKey map[epochtime.EpochTime]*signature.PublicKey

	epoch           epochtime.EpochTime
	connectionEpoch epochtime.EpochTime
}

// GetConnectedNode returns registry node information about the connected
// storage node.
func (b *storageClientBackend) GetConnectedNode() *node.Node {
	b.connectionState.RLock()
	defer b.connectionState.RUnlock()

	return b.connectionState.node
}

func (b *storageClientBackend) updateConnection() {
	b.state.RLock()
	defer b.state.RUnlock()

	b.logger.Debug("storage client: updating connection")

	leaderKey := b.state.storageNodeLeaderKey[b.state.epoch]
	var leader *node.Node
	nodeList := b.state.storageNodeList[b.state.epoch]

	for _, node := range nodeList {
		if node.ID.String() == leaderKey.String() {
			leader = node
			break
		}
	}

	if leader == nil {
		b.logger.Error("storage client: cannot update connection, committee leader not found in node list",
			"leader_key", leaderKey.String(),
			"node_list", nodeList,
		)
		return
	}

	// TODO: should we only update connection if key or address changed
	b.connectionState.Lock()
	defer b.connectionState.Unlock()

	var opts grpc.DialOption
	if leader.Certificate == nil {
		// TODO: This should only happen in tests, where nodes register without Certificate.
		// This can be rejected once node_tests do register with a Certificate.
		opts = grpc.WithInsecure()
		b.logger.Warn("storage client: storage committee leader registered without certificate, using insecure connection!")
	} else {
		nodeCert, err := leader.Certificate.Parse()
		if err != nil {
			return
		}
		certPool := x509.NewCertPool()
		certPool.AddCert(nodeCert)
		creds := credentials.NewClientTLSFromCert(certPool, "ekiden-node")
		opts = grpc.WithTransportCredentials(creds)
	}

	if len(leader.Addresses) == 0 {
		b.logger.Error("storage client: cannot update connection, committee leader does not have any addresses",
			"leader", leader,
		)
		return
	}

	// cleanup previous resolver
	b.connectionState.resolverCleanupCb()

	manualResolver, address, cleanupCb := manual.NewManualResolver()

	conn, err := grpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name))
	if err != nil {
		b.logger.Error("storage client: cannot update connection, failed dialing leader",
			"leader", leader,
			"err", err,
		)
		return
	}
	addresses := []resolver.Address{}
	for _, addr := range leader.Addresses {
		addresses = append(addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.NewAddress(addresses)

	client := storage.NewStorageClient(conn)
	b.logger.Debug("storage client: storage node connection updated",
		"node", leader,
	)

	// XXX: once static single storage node is no longer assumed, make sure
	// to block storage requests on epoch transition, and retry them after
	// the node committee for new epoch is known.
	b.connectionState.client = client
	b.connectionState.conn = conn
	b.connectionState.node = leader
	b.connectionState.resolverCleanupCb = cleanupCb
	b.state.connectionEpoch = b.state.epoch
}

func (s *storageClientBackendState) canUpdateConnection() bool {
	s.RLock()
	defer s.RUnlock()

	return s.storageNodeList[s.epoch] != nil && s.storageNodeLeaderKey[s.epoch] != nil
}

func (s *storageClientBackendState) updateEpoch(epoch epochtime.EpochTime) {
	s.Lock()
	defer s.Unlock()

	if epoch == s.epoch {
		return
	}
	s.logger.Debug("worker: epoch transition",
		"prev_epoch", s.epoch,
		"epoch", epoch,
	)

	s.epoch = epoch
}

func (s *storageClientBackendState) prune() {
	s.Lock()
	defer s.Unlock()

	pruneBefore := s.epoch - 1
	if pruneBefore > s.epoch {
		return
	}

	for epoch := range s.storageNodeList {
		if epoch < pruneBefore {
			delete(s.storageNodeList, epoch)
		}
	}
	for epoch := range s.storageNodeLeaderKey {
		if epoch < pruneBefore {
			delete(s.storageNodeLeaderKey, epoch)
		}
	}
}

func (s *storageClientBackendState) updateStorageNodeList(ctx context.Context, epoch epochtime.EpochTime, nodes []*node.Node) error {
	s.Lock()
	defer s.Unlock()

	// Re-scheduling within epoch not allowed, so if there is node list already there
	// nothing to do.
	if s.storageNodeList[epoch] != nil {
		return nil
	}

	storageNodes := []*node.Node{}
	for _, n := range nodes {
		if n.HasRoles(node.RoleStorageWorker) {
			storageNodes = append(storageNodes, n)
		}
	}
	s.storageNodeList[epoch] = storageNodes

	return nil
}

func (s *storageClientBackendState) updateStorageLeader(ctx context.Context, epoch epochtime.EpochTime, nodeKey signature.PublicKey) error {
	s.Lock()
	defer s.Unlock()

	// XXX: Storage client assumes that all runtimes share the same single storage node
	// leader. We only set the first storage node received for each epoch, and ignore
	// the rest.
	if s.storageNodeLeaderKey[epoch] != nil {
		return nil
	}

	s.storageNodeLeaderKey[epoch] = &nodeKey

	return nil
}

func (b *storageClientBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	var req storage.GetRequest

	req.Id = key[:]

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.Get(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, api.ErrKeyNotFound
		}
		return nil, err
	}

	return resp.GetData(), nil
}

func (b *storageClientBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	var req storage.GetBatchRequest

	req.Ids = make([][]byte, 0, len(keys))
	for _, v := range keys {
		req.Ids = append(req.Ids, append([]byte{}, v[:]...))
	}

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.GetBatch(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	rs := resp.GetData()

	// Fix response by replacing empty parts with nils, as is expected/done by other backends.
	fixedRs := [][]byte{}
	for _, v := range rs {
		if len(v) > 0 {
			fixedRs = append(fixedRs, v)
		} else {
			fixedRs = append(fixedRs, nil)
		}

	}

	return fixedRs, nil
}

func (b *storageClientBackend) GetReceipt(ctx context.Context, keys []api.Key) (*api.SignedReceipt, error) {
	var req storage.GetReceiptRequest

	req.Ids = make([][]byte, 0, len(keys))
	for _, v := range keys {
		req.Ids = append(req.Ids, append([]byte{}, v[:]...))
	}

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.GetReceipt(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	var signed api.SignedReceipt
	if err = signed.UnmarshalCBOR(resp.GetData()); err != nil {
		return nil, err
	}

	return &signed, nil
}

func (b *storageClientBackend) Insert(ctx context.Context, value []byte, expiration uint64, opts api.InsertOptions) error {
	var req storage.InsertRequest

	req.Data = value
	req.Expiry = expiration

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return ErrStorageNotAvailable
	}
	_, err := b.connectionState.client.Insert(ctx, &req)
	b.connectionState.RUnlock()

	return err
}

func (b *storageClientBackend) InsertBatch(ctx context.Context, values []api.Value, opts api.InsertOptions) error {
	var req storage.InsertBatchRequest

	req.Items = make([]*storage.InsertRequest, 0, len(values))
	for _, v := range values {
		value := v.Data
		exp := v.Expiration

		req.Items = append(req.Items, &storage.InsertRequest{
			Data:   value,
			Expiry: exp,
		})
	}

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return ErrStorageNotAvailable
	}
	_, err := b.connectionState.client.InsertBatch(ctx, &req)
	b.connectionState.RUnlock()

	return err
}

func (b *storageClientBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	keys, err := b.connectionState.client.GetKeys(ctx, &storage.GetKeysRequest{})
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	kiCh := make(chan *api.KeyInfo)

	go func() {
		defer close(kiCh)

		for {
			resp, err := keys.Recv()

			switch err {
			case nil:
			case io.EOF:
				return
			}

			ki := &api.KeyInfo{
				Expiration: epochtime.EpochTime(resp.GetExpiry()),
			}
			copy(ki.Key[:], resp.GetKey())

			select {
			case kiCh <- ki:
			case <-ctx.Done():
				return
			}
		}
	}()

	return kiCh, nil
}

func (b *storageClientBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*api.MKVSReceipt, error) {
	var req storage.ApplyRequest
	req.Root, _ = root.MarshalBinary()
	req.ExpectedNewRoot, _ = expectedNewRoot.MarshalBinary()
	req.Log = make([]*storage.LogEntry, 0, len(log))
	for _, e := range log {
		req.Log = append(req.Log, &storage.LogEntry{
			Key:   e.Key,
			Value: e.Value,
		})
	}

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.Apply(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	var receipt api.MKVSReceipt
	if err = receipt.UnmarshalCBOR(resp.GetReceipt()); err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal receipt")
	}

	return &receipt, nil
}

func (b *storageClientBackend) ApplyBatch(ctx context.Context, ops []api.ApplyOp) (*api.MKVSReceipt, error) {
	var req storage.ApplyBatchRequest
	req.Ops = make([]*storage.ApplyOp, 0, len(ops))
	for _, op := range ops {
		var pOp storage.ApplyOp
		pOp.Root, _ = op.Root.MarshalBinary()
		pOp.ExpectedNewRoot, _ = op.ExpectedNewRoot.MarshalBinary()
		pOp.Log = make([]*storage.LogEntry, 0, len(op.WriteLog))
		for _, e := range op.WriteLog {
			pOp.Log = append(pOp.Log, &storage.LogEntry{
				Key:   e.Key,
				Value: e.Value,
			})
		}
		req.Ops = append(req.Ops, &pOp)
	}

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.ApplyBatch(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	var receipt api.MKVSReceipt
	if err = receipt.UnmarshalCBOR(resp.GetReceipt()); err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal receipt")
	}

	return &receipt, nil
}

func (b *storageClientBackend) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	var req storage.GetSubtreeRequest
	req.Root, _ = root.MarshalBinary()
	req.MaxDepth = uint32(maxDepth)
	req.Id = &storage.NodeID{Depth: uint32(id.Depth)}
	req.Id.Path, _ = id.Path.MarshalBinary()

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.GetSubtree(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	var subtree api.Subtree
	if err = subtree.UnmarshalBinary(resp.GetSubtree()); err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal subtree")
	}

	return &subtree, nil
}

func (b *storageClientBackend) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	var req storage.GetPathRequest
	req.Root, _ = root.MarshalBinary()
	req.Key, _ = key.MarshalBinary()
	req.StartDepth = uint32(startDepth)

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.GetPath(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	var subtree api.Subtree
	if err = subtree.UnmarshalBinary(resp.GetSubtree()); err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal subtree")
	}

	return &subtree, nil
}

func (b *storageClientBackend) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	var req storage.GetNodeRequest
	req.Root, _ = root.MarshalBinary()
	req.Id = &storage.NodeID{Depth: uint32(id.Depth)}
	req.Id.Path, _ = id.Path.MarshalBinary()

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.GetNode(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	node, err := urkelDb.NodeUnmarshalBinary(resp.GetNode())
	if err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal node")
	}

	return node, nil
}

func (b *storageClientBackend) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	var req storage.GetValueRequest
	req.Root, _ = root.MarshalBinary()
	req.Id, _ = id.MarshalBinary()

	b.connectionState.RLock()
	if b.connectionState.client == nil {
		b.connectionState.RUnlock()
		return nil, ErrStorageNotAvailable
	}
	resp, err := b.connectionState.client.GetValue(ctx, &req)
	b.connectionState.RUnlock()

	if err != nil {
		return nil, err
	}

	return resp.GetValue(), nil
}

func (b *storageClientBackend) Cleanup() {
	b.connectionState.Lock()
	defer b.connectionState.Unlock()

	b.cancelFn()
	b.connectionState.resolverCleanupCb()
	if b.connectionState.conn != nil {
		b.connectionState.conn.Close()
	}
}

func (b *storageClientBackend) Initialized() <-chan struct{} {
	return b.initCh
}

func (b *storageClientBackend) watcher(ctx context.Context) {
	timeCh, sub := b.timeSource.WatchEpochs()
	defer sub.Close()

	nodeListCh, sub := b.registry.WatchNodeList()
	defer sub.Close()

	schedCh, sub := b.scheduler.WatchCommittees()
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case epoch := <-timeCh:
			b.logger.Debug("worker: epoch transition", "epoch", epoch)
			b.state.updateEpoch(epoch)
			b.state.prune()
		case ev := <-nodeListCh:
			if ev == nil {
				continue
			}
			b.logger.Debug("worker: node list for epoch",
				"epoch", ev.Epoch,
			)

			if err := b.state.updateStorageNodeList(ctx, ev.Epoch, ev.Nodes); err != nil {
				b.logger.Error("worker: failed to update storage list for epoch",
					"err", err,
				)
				continue
			}
		case committee := <-schedCh:
			b.logger.Debug("worker: scheduler committee for epoch",
				"committee", committee,
				"epoch", committee.ValidFor,
				"kind", committee.Kind)

			if committee.Kind != scheduler.Storage {
				continue
			}

			if len(committee.Members) == 0 {
				b.logger.Warn("worker: received empty storage committee")
				continue
			}

			var leader *scheduler.CommitteeNode
			for _, n := range committee.Members {
				if n.Role == scheduler.Leader {
					leader = n
					break
				}
			}

			if leader == nil {
				b.logger.Error("worker: received storage committee without leader")
				continue
			}

			if err := b.state.updateStorageLeader(ctx, committee.ValidFor, leader.PublicKey); err != nil {
				b.logger.Error("worker: failed to update storage leader for epoch",
					"err", err,
				)
				continue
			}
		}

		if b.state.epoch == b.state.connectionEpoch {
			continue
		}
		b.logger.Debug("storage client: epoch changed since last connection")

		if !b.state.canUpdateConnection() {
			continue
		}

		b.updateConnection()
		if !b.signaledInit {
			b.signaledInit = true
			close(b.initCh)
		}
		b.logger.Debug("storage client: updated connection")
	}
}

// New creates a new client
func New(ctx context.Context, epochtimeBackend epochtime.Backend, schedulerBackend scheduler.Backend, registryBackend registry.Backend) (api.Backend, error) {
	logger := logging.GetLogger("storage/client")

	if viper.GetString(cfgDebugClientAddress) != "" {
		logger.Warn("Storage client in debug mode, connecting to provided client",
			"address", cfgDebugClientAddress,
		)

		var opts grpc.DialOption
		if viper.GetString(cfgDebugClientTLSCertFile) != "" {
			creds, err := credentials.NewClientTLSFromFile(viper.GetString(cfgDebugClientTLSCertFile), "ekiden-node")
			if err != nil {
				logger.Error("failed creating grpc tls client from file",
					"file", viper.GetString(cfgDebugClientTLSCertFile),
					"error", err,
				)
				return nil, err
			}
			opts = grpc.WithTransportCredentials(creds)
		} else {
			opts = grpc.WithInsecure()
		}

		conn, err := grpc.Dial(viper.GetString(cfgDebugClientAddress), opts)
		if err != nil {
			logger.Error("unable to dial debug client",
				"error", err,
			)
			return nil, err
		}
		client := storage.NewStorageClient(conn)

		b := &storageClientBackend{
			logger:     logger,
			timeSource: epochtimeBackend,
			scheduler:  schedulerBackend,
			registry:   registryBackend,
			connectionState: &storageClientConnectionState{
				conn:   conn,
				client: client,
			},
			state:  &storageClientBackendState{},
			initCh: make(chan struct{}),
		}
		close(b.initCh)

		return b, nil
	}

	b := &storageClientBackend{
		logger:          logger,
		timeSource:      epochtimeBackend,
		scheduler:       schedulerBackend,
		registry:        registryBackend,
		connectionState: &storageClientConnectionState{resolverCleanupCb: func() {}},
		state: &storageClientBackendState{
			logger:               logger,
			storageNodeList:      make(map[epochtime.EpochTime][]*node.Node),
			storageNodeLeaderKey: make(map[epochtime.EpochTime]*signature.PublicKey),
			epoch:                epochtime.EpochInvalid,
			connectionEpoch:      epochtime.EpochInvalid,
		},
		initCh: make(chan struct{}),
	}

	b.haltCtx, b.cancelFn = context.WithCancel(ctx)

	go b.watcher(ctx)

	return b, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgDebugClientAddress, "", "Address of node to connect to with the storage client")
		cmd.Flags().String(cfgDebugClientTLSCertFile, "", "Path to tls certificate for grpc")
	}

	for _, v := range []string{
		cfgDebugClientAddress,
		cfgDebugClientTLSCertFile,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
