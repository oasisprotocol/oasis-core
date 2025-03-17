package full

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	abcicli "github.com/cometbft/cometbft/abci/client"
	cmtconfig "github.com/cometbft/cometbft/config"
	cmtsync "github.com/cometbft/cometbft/libs/sync"
	cmtnode "github.com/cometbft/cometbft/node"
	cmtproxy "github.com/cometbft/cometbft/proxy"
	cmtcore "github.com/cometbft/cometbft/rpc/core"
	"github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

var _ api.Backend = (*archiveService)(nil)

type archiveService struct {
	sync.Mutex
	*commonNode

	abciClient abcicli.Client
	eb         *cmttypes.EventBus

	quitCh chan struct{}

	stopOnce sync.Once
}

// Implements consensusAPI.Backend.
func (srv *archiveService) Start() error {
	if srv.started() {
		return fmt.Errorf("cometbft: service already started")
	}

	if err := srv.eb.Start(); err != nil {
		return err
	}

	if err := srv.commonNode.start(); err != nil {
		return err
	}

	if err := srv.abciClient.Start(); err != nil {
		return err
	}

	// Make sure the quit channel is closed when the node shuts down.
	go func() {
		select {
		case <-srv.quitCh:
		case <-srv.mux.Quit():
			select {
			case <-srv.quitCh:
			default:
				close(srv.quitCh)
			}
		}
	}()

	// Start command dispatchers for all the service clients.
	srv.serviceClientsWg.Add(len(srv.serviceClients))
	for _, svc := range srv.serviceClients {
		go func() {
			defer srv.serviceClientsWg.Done()
			srv.serviceClientWorker(srv.ctx, svc)
		}()
	}

	srv.commonNode.finishStart()

	return nil
}

// Implements consensusAPI.Backend.
func (srv *archiveService) Stop() {
	if !srv.started() {
		return
	}

	srv.stopOnce.Do(func() {
		if err := srv.abciClient.Stop(); err != nil {
			srv.Logger.Error("error on stopping abci client", "err", err)
		}
		srv.commonNode.stop()
	})
}

// Implements consensusAPI.Backend.
func (srv *archiveService) Quit() <-chan struct{} {
	return srv.quitCh
}

// Implements consensusAPI.Backend.
func (srv *archiveService) Synced() <-chan struct{} {
	// Archive node is always considered synced.
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Implements consensusAPI.Backend.
func (srv *archiveService) SupportedFeatures() consensusAPI.FeatureMask {
	return consensusAPI.FeatureServices | consensusAPI.FeatureArchiveNode
}

// Implements consensusAPI.Backend.
func (srv *archiveService) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	status, err := srv.commonNode.GetStatus(ctx)
	if err != nil {
		return nil, err
	}
	status.Status = consensusAPI.StatusStateReady

	return status, nil
}

// Implements consensusAPI.Backend.
func (srv *archiveService) EstimateGas(context.Context, *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	return 0, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (srv *archiveService) GetSignerNonce(context.Context, *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	return 0, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (srv *archiveService) WatchBlocks(ctx context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)
	ch := make(chan *consensusAPI.Block)
	go func() {
		defer close(ch)
		<-ctx.Done()
	}()
	return ch, sub, nil
}

// NewArchive creates a new archive-only consensus service.
func NewArchive(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	genesisDoc *genesisAPI.Document,
) (consensusAPI.Backend, error) {
	commonNode, err := newCommonNode(ctx, dataDir, identity, genesisDoc)
	if err != nil {
		return nil, err
	}

	srv := &archiveService{
		commonNode: commonNode,
		quitCh:     make(chan struct{}),
	}
	// Common node needs access to parent struct for initializing consensus services.
	srv.commonNode.parentNode = srv

	appConfig := &abci.ApplicationConfig{
		DataDir:        filepath.Join(srv.dataDir, tmcommon.StateDir),
		StorageBackend: config.GlobalConfig.Storage.Backend,
		Pruning: abci.PruneConfig{
			Strategy:      abci.PruneNone,
			PruneInterval: time.Hour * 100, // Irrelevant as pruning is disabled.
		},
		Identity:            srv.identity,
		DisableCheckpointer: true,
		InitialHeight:       uint64(srv.genesis.Height),
		// ReadOnly should actually be preferable for archive but there is a badger issue with read-only:
		// https://discuss.dgraph.io/t/read-only-log-truncate-required-to-run-db/16444/2
		ReadOnlyStorage: false,
		ChainContext:    srv.genesis.ChainContext(),
	}
	srv.mux, err = abci.NewApplicationServer(srv.ctx, nil, appConfig)
	if err != nil {
		return nil, fmt.Errorf("cometbft/archive: failed to create application server: %w", err)
	}

	// Setup needed CometBFT services.
	logger := tmcommon.NewLogAdapter(!config.GlobalConfig.Consensus.LogDebug)
	srv.abciClient = abcicli.NewLocalClient(new(cmtsync.Mutex), srv.mux.Mux())

	dbProvider, err := db.GetProvider()
	if err != nil {
		return nil, err
	}
	cmtConfig := cmtconfig.DefaultConfig()
	_ = viper.Unmarshal(&cmtConfig)
	cmtConfig.SetRoot(filepath.Join(srv.dataDir, tmcommon.StateDir))

	// NOTE: DBContext uses a full CometBFT config but the only thing that is actually used
	// is the data dir field.
	srv.blockStoreDB, err = dbProvider(&cmtnode.DBContext{ID: "blockstore", Config: cmtConfig})
	if err != nil {
		return nil, err
	}
	srv.blockStoreDB = db.WithCloser(srv.blockStoreDB, srv.dbCloser)

	// NOTE: DBContext uses a full CometBFT config but the only thing that is actually used
	// is the data dir field.
	var stateDB dbm.DB
	stateDB, err = dbProvider(&cmtnode.DBContext{ID: "state", Config: cmtConfig})
	if err != nil {
		return nil, err
	}
	stateDB = db.WithCloser(stateDB, srv.dbCloser)
	srv.stateStore = state.NewStore(stateDB, state.StoreOptions{})

	tmGenDoc, err := api.GetCometBFTGenesisDocument(genesisDoc)
	if err != nil {
		return nil, err
	}

	srv.eb = cmttypes.NewEventBus()
	// Setup minimal CometBFT environment needed to support consensus queries.
	cmtcore.SetEnvironment(&cmtcore.Environment{
		ProxyAppQuery:    cmtproxy.NewAppConnQuery(srv.abciClient, nil),
		ProxyAppMempool:  nil,
		StateStore:       srv.stateStore,
		BlockStore:       store.NewBlockStore(srv.blockStoreDB),
		EvidencePool:     state.EmptyEvidencePool{},
		ConsensusState:   nil,
		GenDoc:           tmGenDoc,
		Logger:           logger,
		Config:           *cmtConfig.RPC,
		EventBus:         srv.eb,
		P2PPeers:         nil,
		P2PTransport:     nil,
		PubKey:           nil,
		TxIndexer:        nil,
		BlockIndexer:     nil,
		ConsensusReactor: nil,
		Mempool:          nil,
	})

	return srv, srv.initialize()
}

// serviceClientWorker handles command dispatching.
func (srv *archiveService) serviceClientWorker(ctx context.Context, svc api.ServiceClient) {
	sd := svc.ServiceDescriptor()
	if sd == nil {
		// Some services don't actually need a worker.
		return
	}

	// Archive only handles commands.
	cmdCh := sd.Commands()
	if cmdCh == nil {
		// Services without commands do not need a worker.
		return
	}

	logger := srv.Logger.With("service", sd.Name())
	logger.Info("starting command dispatcher")

	// Fetch and remember the latest block. This won't change on an archive node.
	latestBlock, err := srv.commonNode.GetBlock(ctx, consensusAPI.HeightLatest)
	if err != nil {
		logger.Error("failed to fetch latest block",
			"err", err,
		)
		return
	}

	// Service client event loop.
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-cmdCh:
			if err := svc.DeliverCommand(ctx, latestBlock.Height, cmd); err != nil {
				logger.Error("failed to deliver command to service client",
					"err", err,
				)
				continue
			}
		}
	}
}
