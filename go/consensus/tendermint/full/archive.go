package full

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/viper"
	abcicli "github.com/tendermint/tendermint/abci/client"
	tmconfig "github.com/tendermint/tendermint/config"
	tmsync "github.com/tendermint/tendermint/libs/sync"
	tmnode "github.com/tendermint/tendermint/node"
	tmproxy "github.com/tendermint/tendermint/proxy"
	tmcore "github.com/tendermint/tendermint/rpc/core"
	"github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/store"
	tdbm "github.com/tendermint/tm-db"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
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
func (srv *archiveService) Mode() consensusAPI.Mode {
	return consensusAPI.ModeArchive
}

// Implements consensusAPI.Backend.
func (srv *archiveService) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	status, err := srv.commonNode.GetStatus(ctx)
	if err != nil {
		return nil, err
	}
	status.Status = consensusAPI.StatusStateReady
	status.Mode = consensusAPI.ModeArchive

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
		HaltEpochHeight:     srv.genesis.HaltEpoch,
		OwnTxSigner:         srv.identity.NodeSigner.Public(),
		DisableCheckpointer: true,
		InitialHeight:       uint64(srv.genesis.Height),
		// ReadOnly should actually be preferable for archive but there is a badger issue with read-only:
		// https://discuss.dgraph.io/t/read-only-log-truncate-required-to-run-db/16444/2
		ReadOnlyStorage: false,
	}
	srv.mux, err = abci.NewApplicationServer(srv.ctx, nil, appConfig)
	if err != nil {
		return nil, fmt.Errorf("tendermint/archive: failed to create application server: %w", err)
	}

	// Setup needed tendermint services.
	logger := tmcommon.NewLogAdapter(!viper.GetBool(tmcommon.CfgLogDebug))
	srv.abciClient = abcicli.NewLocalClient(new(tmsync.Mutex), srv.mux.Mux())

	dbProvider, err := db.GetProvider()
	if err != nil {
		return nil, err
	}
	tmConfig := tmconfig.DefaultConfig()
	_ = viper.Unmarshal(&tmConfig)
	tmConfig.SetRoot(filepath.Join(srv.dataDir, tmcommon.StateDir))

	// NOTE: DBContext uses a full tendermint config but the only thing that is actually used
	// is the data dir field.
	srv.blockStoreDB, err = dbProvider(&tmnode.DBContext{ID: "blockstore", Config: tmConfig})
	if err != nil {
		return nil, err
	}
	srv.blockStoreDB = db.WithCloser(srv.blockStoreDB, srv.dbCloser)

	// NOTE: DBContext uses a full tendermint config but the only thing that is actually used
	// is the data dir field.
	var stateDB tdbm.DB
	stateDB, err = dbProvider(&tmnode.DBContext{ID: "state", Config: tmConfig})
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
	tmcore.SetEnvironment(&tmcore.Environment{
		ProxyAppQuery:    tmproxy.NewAppConnQuery(srv.abciClient),
		ProxyAppMempool:  nil,
		StateStore:       srv.stateStore,
		BlockStore:       store.NewBlockStore(srv.blockStoreDB),
		EvidencePool:     state.EmptyEvidencePool{},
		ConsensusState:   nil,
		GenDoc:           tmGenDoc,
		Logger:           logger,
		Config:           *tmConfig.RPC,
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
