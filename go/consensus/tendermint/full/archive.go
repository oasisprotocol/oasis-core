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
	tmrpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	"github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/store"
	tmdb "github.com/tendermint/tm-db"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmservice "github.com/oasisprotocol/oasis-core/go/common/service"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	cmbackground "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
)

var _ api.Backend = (*archiveService)(nil)

type archiveService struct {
	sync.Mutex
	commonNode

	abciClient abcicli.Client

	isStarted bool

	startedCh chan struct{}
	quitCh    chan struct{}

	stopOnce sync.Once
}

func (srv *archiveService) started() bool {
	srv.Lock()
	defer srv.Unlock()

	return srv.isStarted
}

// Start starts the service.
func (srv *archiveService) Start() error {
	if srv.started() {
		return fmt.Errorf("tendermint: service already started")
	}

	if err := srv.commonNode.Start(); err != nil {
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

	srv.Lock()
	srv.isStarted = true
	srv.Unlock()
	close(srv.startedCh)

	return nil
}

// Stop halts the service.
func (srv *archiveService) Stop() {
	if !srv.started() {
		return
	}
	srv.stopOnce.Do(func() {
		if err := srv.abciClient.Stop(); err != nil {
			srv.Logger.Error("error on stopping abci client", "err", err)
		}
		srv.commonNode.Stop()
	})
}

// Quit returns a channel that will be closed when the service terminates.
func (srv *archiveService) Quit() <-chan struct{} {
	return srv.quitCh
}

// Implements Backend.
func (srv *archiveService) Synced() <-chan struct{} {
	// Archive node is always considered synced.
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Implements Backend.
func (srv *archiveService) EstimateGas(ctx context.Context, req *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	return 0, consensusAPI.ErrUnsupported
}

// Implements Backend.
func (srv *archiveService) GetSignerNonce(ctx context.Context, req *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	return 0, consensusAPI.ErrUnsupported
}

// New creates a new archive-only consensus service.
func NewArchive(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	genesisProvider genesisAPI.Provider,
) (consensusAPI.Backend, error) {
	var err error

	srv := &archiveService{
		commonNode: commonNode{
			BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
			ctx:                   ctx,
			rpcCtx:                &tmrpctypes.Context{},
			identity:              identity,
			dataDir:               dataDir,
			svcMgr:                cmbackground.NewServiceManager(logging.GetLogger("tendermint/servicemanager")),
			startedCh:             make(chan struct{}),
		},
		startedCh: make(chan struct{}),
		quitCh:    make(chan struct{}),
	}
	// Common node needs access to parent struct for initializing consensus services.
	srv.commonNode.parentNode = srv

	doc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, fmt.Errorf("tendermint/archive: failed to get genesis document: %w", err)
	}
	srv.genesis = doc

	appConfig := &abci.ApplicationConfig{
		DataDir:        filepath.Join(srv.dataDir, tmcommon.StateDir),
		StorageBackend: db.GetBackendName(),
		Pruning: abci.PruneConfig{
			Strategy: abci.PruneNone,
		},
		DisableCheckpointer:       true,
		CheckpointerCheckInterval: 100 * time.Hour, // Disabled.
		HaltEpochHeight:           srv.genesis.HaltEpoch,
		OwnTxSigner:               srv.identity.NodeSigner.Public(),
		InitialHeight:             uint64(srv.genesis.Height),
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

	// NOTE: DBContext uses a full tendermint config but the only thing that is actually used
	// is the data dir field.
	var stateDB tmdb.DB
	stateDB, err = dbProvider(&tmnode.DBContext{ID: "state", Config: tmConfig})
	if err != nil {
		return nil, err
	}
	srv.stateStore = state.NewStore(stateDB)

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
		EvidencePool:     nil,
		ConsensusState:   nil,
		GenDoc:           tmGenDoc,
		Logger:           logger,
		Config:           *tmConfig.RPC,
		EventBus:         nil,
		P2PPeers:         nil,
		P2PTransport:     nil,
		PubKey:           nil,
		TxIndexer:        nil,
		ConsensusReactor: nil,
		Mempool:          nil,
	})

	return srv, srv.initialize()
}
