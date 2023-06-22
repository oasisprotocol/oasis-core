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
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

var _ api.Backend = (*archiveService)(nil)

type archiveService struct {
	sync.Mutex
	*commonNode

	abciClient abcicli.Client

	quitCh chan struct{}

	stopOnce sync.Once
}

// Implements consensusAPI.Backend.
func (srv *archiveService) Start() error {
	if srv.started() {
		return fmt.Errorf("tendermint: service already started")
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
func (srv *archiveService) EstimateGas(ctx context.Context, req *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	return 0, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (srv *archiveService) GetSignerNonce(ctx context.Context, req *consensusAPI.GetSignerNonceRequest) (uint64, error) {
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
	genesisProvider genesisAPI.Provider,
) (consensusAPI.Backend, error) {
	commonNode, err := newCommonNode(ctx, dataDir, identity, genesisProvider)
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
		StorageBackend: db.GetBackendName(),
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
		return nil, fmt.Errorf("tendermint/archive: failed to create application server: %w", err)
	}

	// Setup needed tendermint services.
	logger := tmcommon.NewLogAdapter(!config.GlobalConfig.Consensus.LogDebug)
	srv.abciClient = abcicli.NewLocalClient(new(cmtsync.Mutex), srv.mux.Mux())

	dbProvider, err := db.GetProvider()
	if err != nil {
		return nil, err
	}
	cmtConfig := cmtconfig.DefaultConfig()
	_ = viper.Unmarshal(&cmtConfig)
	cmtConfig.SetRoot(filepath.Join(srv.dataDir, tmcommon.StateDir))

	// NOTE: DBContext uses a full tendermint config but the only thing that is actually used
	// is the data dir field.
	srv.blockStoreDB, err = dbProvider(&cmtnode.DBContext{ID: "blockstore", Config: cmtConfig})
	if err != nil {
		return nil, err
	}
	srv.blockStoreDB = db.WithCloser(srv.blockStoreDB, srv.dbCloser)

	// NOTE: DBContext uses a full tendermint config but the only thing that is actually used
	// is the data dir field.
	var stateDB dbm.DB
	stateDB, err = dbProvider(&cmtnode.DBContext{ID: "state", Config: cmtConfig})
	if err != nil {
		return nil, err
	}
	stateDB = db.WithCloser(stateDB, srv.dbCloser)
	srv.stateStore = state.NewStore(stateDB, state.StoreOptions{})

	tmGenDoc, err := api.GetTendermintGenesisDocument(genesisProvider)
	if err != nil {
		return nil, err
	}

	// Setup minimal tendermint environment needed to support consensus queries.
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
		EventBus:         nil,
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
