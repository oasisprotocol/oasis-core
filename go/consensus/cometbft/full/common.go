package full

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"

	dbm "github.com/cometbft/cometbft-db"
	cmtmerkle "github.com/cometbft/cometbft/crypto/merkle"
	cmtcore "github.com/cometbft/cometbft/rpc/core"
	cmtcoretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmtrpctypes "github.com/cometbft/cometbft/rpc/jsonrpc/types"
	"github.com/cometbft/cometbft/state"
	"github.com/cometbft/cometbft/store"
	cmttypes "github.com/cometbft/cometbft/types"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	cmservice "github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon"
	governanceApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/governance"
	keymanagerApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager"
	registryApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry"
	roothashApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash"
	schedulerApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler"
	stakingApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/staking"
	supplementarysanityApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/supplementarysanity"
	vaultApp "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/vault"
	tmbeacon "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/beacon"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db"
	tmgovernance "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/governance"
	tmkeymanager "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/keymanager"
	tmregistry "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/registry"
	tmroothash "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/roothash"
	tmscheduler "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/scheduler"
	tmstaking "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/staking"
	tmvault "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/vault"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governanceAPI "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanagerAPI "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmbackground "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/registry"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	schedulerAPI "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	vaultAPI "github.com/oasisprotocol/oasis-core/go/vault/api"
)

// Possible internal node states.
const (
	stateNotReady    = 0
	stateInitialized = 1
	stateStarted     = 2
	stateStopping    = 3
)

// CommonConfig contains configuration parameters shared across all nodes.
type CommonConfig struct {
	// DataDir is the path to the node's data directory.
	DataDir string
	// Identity is the node's cryptographic identity.
	Identity *identity.Identity
	// ChainID is the unique identifier of the chain.
	ChainID string
	// ChainContext is the chain's domain separation context.
	ChainContext string
	// Genesis provides access to the genesis document.
	Genesis genesisAPI.Provider
	// GenesisDoc is the CometBFT genesis document.
	GenesisDoc *cmttypes.GenesisDoc
	// GenesisHeight is the block height at which the genesis document
	// was generated.
	GenesisHeight int64
	// BaseEpoch is the starting epoch.
	BaseEpoch beaconAPI.EpochTime
	// BaseHeight is the starting height.
	BaseHeight int64
	// PublicKeyBlacklist is the network-wide public key blacklist.
	PublicKeyBlacklist []signature.PublicKey
}

// commonNode implements the common CometBFT node functionality shared between
// full and archive nodes.
type commonNode struct {
	sync.Mutex
	cmservice.BaseBackgroundService

	svcMgr *cmbackground.ServiceManager

	serviceClients   []api.ServiceClient
	serviceClientsWg sync.WaitGroup

	ctx    context.Context
	rpcCtx *cmtrpctypes.Context

	dataDir            string
	identity           *identity.Identity
	chainID            string
	chainContext       string
	genesis            genesisAPI.Provider
	genesisDoc         *cmttypes.GenesisDoc
	genesisHeight      int64
	baseEpoch          beaconAPI.EpochTime
	baseHeight         int64
	publicKeyBlacklist []signature.PublicKey

	mux     *abci.ApplicationServer
	querier *abci.QueryFactory

	beacon     *tmbeacon.ServiceClient
	governance *tmgovernance.ServiceClient
	keymanager *tmkeymanager.ServiceClient
	registry   *tmregistry.ServiceClient
	roothash   *tmroothash.ServiceClient
	scheduler  *tmscheduler.ServiceClient
	staking    *tmstaking.ServiceClient
	vault      *tmvault.ServiceClient

	// These stores must be populated by the parent before the node is deemed ready.
	blockStoreDB dbm.DB
	stateStore   state.Store
	dbCloser     *db.Closer

	state     uint32
	startedCh chan struct{}

	parentNode consensusAPI.Backend
}

func (n *commonNode) initialized() bool {
	return atomic.LoadUint32(&n.state) >= stateInitialized
}

func (n *commonNode) started() bool {
	return atomic.LoadUint32(&n.state) >= stateStarted
}

func (n *commonNode) ensureStarted(ctx context.Context) error {
	// Make sure that the CometBFT service is setup and started.
	select {
	case <-n.startedCh:
	case <-n.ctx.Done():
		return n.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}

	if atomic.LoadUint32(&n.state) >= stateStopping {
		return fmt.Errorf("node is shutting down")
	}

	return nil
}

// start starts the common node services.
//
// Note that this explicitly does not finish startup (e.g. the common node will still be considered
// not started after this method is called) and it is the caller's job to do so by calling the
// finishStart method.
func (n *commonNode) start() error {
	n.Lock()
	defer n.Unlock()

	if atomic.LoadUint32(&n.state) != stateInitialized {
		return fmt.Errorf("cometbft/common_node: not in initialized state")
	}

	return n.mux.Start()
}

func (n *commonNode) finishStart() {
	atomic.StoreUint32(&n.state, stateStarted)
	close(n.startedCh)
}

func (n *commonNode) stop() {
	n.Lock()
	defer n.Unlock()

	if !n.started() {
		return
	}

	n.svcMgr.Stop()
	n.mux.Stop()

	atomic.StoreUint32(&n.state, stateStopping)
}

func (n *commonNode) initialize() error {
	n.Lock()
	defer n.Unlock()

	if atomic.LoadUint32(&n.state) != stateNotReady {
		return nil
	}

	// Apply the genesis public key blacklist.
	for _, v := range n.publicKeyBlacklist {
		if err := v.Blacklist(); err != nil {
			n.Logger.Error("initialize: failed to blacklist key",
				"err", err,
				"pk", v,
			)
			return err
		}
	}

	// Fetch the application state.
	state := n.mux.State()
	md := n.mux.MessageDispatcher()

	// Initialize consensus backend querier.
	n.querier = abci.NewQueryFactory(state)

	// Initialize backends.
	n.beacon = tmbeacon.New(n.baseEpoch, n.baseHeight, n.parentNode, beaconApp.NewQueryFactory(state))
	n.governance = tmgovernance.New(n.parentNode, governanceApp.NewQueryFactory(state))
	n.keymanager = tmkeymanager.New(keymanagerApp.NewQueryFactory(state))
	n.registry = tmregistry.New(n.parentNode, registryApp.NewQueryFactory(state))
	n.roothash = tmroothash.New(n.parentNode, roothashApp.NewQueryFactory(state))
	n.scheduler = tmscheduler.New(schedulerApp.NewQueryFactory(state))
	n.staking = tmstaking.New(n.parentNode, stakingApp.NewQueryFactory(state))
	n.vault = tmvault.New(n.parentNode, vaultApp.NewQueryFactory(state))

	n.serviceClients = []api.ServiceClient{
		n.beacon,
		n.governance,
		n.keymanager,
		n.registry,
		n.roothash,
		n.scheduler,
		n.staking,
		n.vault,
	}

	// Register CometBFT applications.
	beaconApp := beaconApp.New()
	governanceApp := governanceApp.New(state, md)
	keymanagerApp := keymanagerApp.New(state)
	registryApp := registryApp.New(state, md)
	roothashApp := roothashApp.New(state, md, n.roothash)
	schedulerApp := schedulerApp.New(state, md)
	stakingApp := stakingApp.New(state, md)
	vaultApp := vaultApp.New(state, md)

	apps := []api.Application{
		beaconApp,
		governanceApp,
		keymanagerApp,
		registryApp,
		roothashApp,
		schedulerApp,
		stakingApp,
		vaultApp,
	}
	for _, app := range apps {
		if err := n.mux.Register(app); err != nil {
			return fmt.Errorf("failed to register app: %w", err)
		}
		app.Subscribe()
	}

	// Enable supplementary sanity checks when enabled.
	if config.GlobalConfig.Consensus.SupplementarySanity.Enabled {
		app := supplementarysanityApp.New(state, int64(config.GlobalConfig.Consensus.SupplementarySanity.Interval))
		if err := n.mux.Register(app); err != nil {
			return fmt.Errorf("failed to register supplementary sanity check app: %w", err)
		}
	}

	// Configure the beacon application as an epochtime.
	if err := n.mux.SetEpochtime(n.beacon); err != nil {
		return err
	}

	// Configure the staking application as a fee handler.
	if err := n.mux.SetTransactionAuthHandler(stakingApp); err != nil {
		return err
	}

	// Start metrics.
	if cmmetrics.Enabled() {
		rmu := registry.NewMetricsUpdater(n.ctx, n.registry)
		n.svcMgr.RegisterCleanupOnly(rmu, "registry metrics updater")
	}

	atomic.StoreUint32(&n.state, stateInitialized)

	return nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) Started() <-chan struct{} {
	return n.startedCh
}

// Implements consensusAPI.Backend.
func (n *commonNode) Cleanup() {
	n.serviceClientsWg.Wait()
	n.svcMgr.Cleanup()
	n.dbCloser.Close()
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetAddresses() ([]node.ConsensusAddress, error) {
	u, err := common.GetExternalAddress()
	if err != nil {
		return nil, err
	}

	var addr node.ConsensusAddress
	if err = addr.Address.UnmarshalText([]byte(u.Host)); err != nil {
		return nil, fmt.Errorf("cometbft: failed to parse external address host: %w", err)
	}
	addr.ID = n.identity.P2PSigner.Public()

	return []node.ConsensusAddress{addr}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) Checkpointer() checkpoint.Checkpointer {
	return n.mux.State().Checkpointer()
}

// Implements consensusAPI.Backend.
func (n *commonNode) StateToGenesis(ctx context.Context, height int64) (*genesisAPI.Document, error) {
	blk, err := n.GetCometBFTBlock(ctx, height)
	if err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, consensusAPI.ErrNoCommittedBlocks
	}
	height = blk.Header.Height

	// Query root consensus parameters.
	q, err := n.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}
	cp, err := q.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	// Call StateToGenesis on all backends and merge the results together.
	beaconGenesis, err := n.Beacon().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	registryGenesis, err := n.Registry().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	roothashGenesis, err := n.RootHash().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	stakingGenesis, err := n.Staking().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	keymanagerGenesis, err := n.KeyManager().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	schedulerGenesis, err := n.Scheduler().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	governanceGenesis, err := n.Governance().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	vaultGenesis, err := n.Vault().StateToGenesis(ctx, height)
	if err != nil {
		return nil, err
	}

	return &genesisAPI.Document{
		Height:     height,
		ChainID:    n.chainID,
		Time:       blk.Header.Time,
		Beacon:     *beaconGenesis,
		Registry:   *registryGenesis,
		RootHash:   *roothashGenesis,
		Staking:    *stakingGenesis,
		Governance: *governanceGenesis,
		Vault:      vaultGenesis,
		KeyManager: *keymanagerGenesis,
		Scheduler:  *schedulerGenesis,
		Consensus: consensusGenesis.Genesis{
			Backend:    api.BackendName,
			Parameters: *cp,
		},
	}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetGenesisDocument(context.Context) (*genesisAPI.Document, error) {
	return n.genesis.GetGenesisDocument()
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetChainContext(context.Context) (string, error) {
	return n.chainContext, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) Beacon() beaconAPI.Backend {
	return n.beacon
}

// Implements consensusAPI.Backend.
func (n *commonNode) Core() consensusAPI.Backend {
	return n.parentNode
}

// Implements consensusAPI.Backend.
func (n *commonNode) KeyManager() keymanagerAPI.Backend {
	return n.keymanager
}

// Implements consensusAPI.Backend.
func (n *commonNode) Registry() registryAPI.Backend {
	return n.registry
}

// Implements consensusAPI.Backend.
func (n *commonNode) RootHash() roothashAPI.Backend {
	return n.roothash
}

// Implements consensusAPI.Backend.
func (n *commonNode) Staking() stakingAPI.Backend {
	return n.staking
}

// Implements consensusAPI.Backend.
func (n *commonNode) Scheduler() schedulerAPI.Backend {
	return n.scheduler
}

// Implements consensusAPI.Backend.
func (n *commonNode) Governance() governanceAPI.Backend {
	return n.governance
}

// Implements consensusAPI.Backend.
func (n *commonNode) Vault() vaultAPI.Backend {
	return n.vault
}

// Implements consensusAPI.Backend.
func (n *commonNode) EstimateGas(_ context.Context, req *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	return n.mux.EstimateGas(req.Signer, req.Transaction)
}

// Implements consensusAPI.Backend.
func (n *commonNode) MinGasPrice(ctx context.Context) (*quantity.Quantity, error) {
	q, err := n.querier.QueryAt(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return nil, err
	}
	cp, err := q.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}
	return quantity.NewFromUint64(cp.MinGasPrice), nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) Pruner() consensusAPI.StatePruner {
	return n.mux.Pruner()
}

func (n *commonNode) heightToCometBFTHeight(height int64) (int64, error) {
	if height == consensusAPI.HeightLatest {
		// Do not let CometBFT determine the latest height (e.g., by passing nil) as that
		// completely ignores ABCI processing so it can return a block for which local state does
		// not yet exist. Use our mux notion of latest height instead.
		tmHeight := n.mux.State().BlockHeight()
		if tmHeight == 0 {
			// No committed blocks yet.
			return 0, consensusAPI.ErrNoCommittedBlocks
		}
		return tmHeight, nil
	}

	return height, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetSignerNonce(ctx context.Context, req *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	acct, err := n.Staking().Account(ctx, &stakingAPI.OwnerQuery{
		Height: req.Height,
		Owner:  req.AccountAddress,
	})
	if err != nil {
		return 0, err
	}

	return acct.General.Nonce, nil
}

// GetCometBFTBlock returns the CometBFT block at the specified height.
func (n *commonNode) GetCometBFTBlock(ctx context.Context, height int64) (*cmttypes.Block, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := n.heightToCometBFTHeight(height)
	switch err {
	case nil:
		// Continues bellow.
	case consensusAPI.ErrNoCommittedBlocks:
		// No committed blocks yet.
		return nil, nil
	default:
		return nil, err
	}
	result, err := cmtcore.Block(n.rpcCtx, &tmHeight)
	if err != nil {
		return nil, fmt.Errorf("cometbft: block query failed: %w", err)
	}
	return result.Block, nil
}

// GetCometBFTBlockResults returns the ABCI results from processing a block
// at a specific height.
func (n *commonNode) GetCometBFTBlockResults(ctx context.Context, height int64) (*cmtcoretypes.ResultBlockResults, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := n.heightToCometBFTHeight(height)
	if err != nil {
		return nil, err
	}
	results, err := cmtcore.BlockResults(n.rpcCtx, &tmHeight)
	if err != nil {
		return nil, fmt.Errorf("cometbft: block results query failed: %w", err)
	}

	return results, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetBlock(ctx context.Context, height int64) (*consensusAPI.Block, error) {
	blk, err := n.GetCometBFTBlock(ctx, height)
	if err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, consensusAPI.ErrNoCommittedBlocks
	}

	return api.NewBlock(blk), nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetBlockResults(ctx context.Context, height int64) (*consensusAPI.BlockResults, error) {
	results, err := n.GetCometBFTBlockResults(ctx, height)
	if err != nil {
		return nil, err
	}

	return api.NewBlockResults(results), nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetLightBlock(ctx context.Context, height int64) (*consensusAPI.LightBlock, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := n.heightToCometBFTHeight(height)
	if err != nil {
		return nil, err
	}

	var lb cmttypes.LightBlock

	// Don't use the client as that imposes stupid pagination. Access the state database directly.
	lb.ValidatorSet, err = n.stateStore.LoadValidators(tmHeight)
	if err != nil {
		return nil, consensusAPI.ErrVersionNotFound
	}

	commit, err := cmtcore.Commit(n.rpcCtx, &tmHeight)
	if err == nil && commit != nil && commit.Header != nil {
		lb.SignedHeader = &commit.SignedHeader
		tmHeight = commit.Header.Height
	}

	protoLb, err := lb.ToProto()
	if err != nil {
		return nil, fmt.Errorf("cometbft: failed to convert light block: %w", err)
	}
	if protoLb.ValidatorSet != nil {
		// ToProto sets the TotalVotingPower to 0, but the rust side FromProto requires it.
		// https://github.com/tendermint/tendermint/blob/41c176ccc6a75d25631d0f891efb2e19a33329dc/types/validator_set.go#L949-L951
		// https://github.com/informalsystems/tendermint-rs/blob/c70f6eea9ccd1f41c0a608c5285b6af98b66c9fe/tendermint/src/validator.rs#L38-L45
		protoLb.ValidatorSet.TotalVotingPower = lb.ValidatorSet.TotalVotingPower()
	}

	meta, err := protoLb.Marshal()
	if err != nil {
		return nil, fmt.Errorf("cometbft: failed to marshal light block: %w", err)
	}

	return &consensusAPI.LightBlock{
		Height: tmHeight,
		Meta:   meta,
	}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetLatestHeight(context.Context) (int64, error) {
	return n.heightToCometBFTHeight(consensusAPI.HeightLatest)
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetLastRetainedHeight(ctx context.Context) (int64, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return 0, err
	}
	state := store.LoadBlockStoreState(n.blockStoreDB)

	// Some pruning configurations return 0 instead of a valid block height.
	// Clamp those to the genesis height.
	return max(state.Base, n.genesisHeight), nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	blk, err := n.GetCometBFTBlock(ctx, height)
	if err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, consensusAPI.ErrNoCommittedBlocks
	}

	txs := make([][]byte, 0, len(blk.Data.Txs))
	for _, tx := range blk.Data.Txs {
		txs = append(txs, tx[:])
	}
	return txs, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetTransactionsWithResults(ctx context.Context, height int64) (*consensusAPI.TransactionsWithResults, error) {
	// Ensure all queries use the same height if the specified height is the latest.
	tmHeight, err := n.heightToCometBFTHeight(height)
	if err != nil {
		return nil, err
	}

	txs, err := n.GetTransactions(ctx, tmHeight)
	if err != nil {
		return nil, err
	}

	blockResults, err := n.GetCometBFTBlockResults(ctx, tmHeight)
	if err != nil {
		return nil, err
	}

	txResults := make([]*results.Result, 0, len(txs))
	for idx, rs := range blockResults.TxsResults {
		// Transaction result.
		result := &results.Result{
			Error: results.Error{
				Module:  rs.GetCodespace(),
				Code:    rs.GetCode(),
				Message: rs.GetLog(),
			},
			GasUsed: uint64(rs.GetGasUsed()),
		}

		// Transaction staking events.
		stakingEvents, err := tmstaking.EventsFromCometBFT(txs[idx], tmHeight, rs.Events)
		if err != nil {
			return nil, err
		}
		for _, e := range stakingEvents {
			result.Events = append(result.Events, &results.Event{Staking: e})
		}

		// Transaction registry events.
		registryEvents, _, err := tmregistry.EventsFromCometBFT(txs[idx], tmHeight, rs.Events)
		if err != nil {
			return nil, err
		}
		for _, e := range registryEvents {
			result.Events = append(result.Events, &results.Event{Registry: e})
		}

		// Transaction roothash events.
		roothashEvents, err := tmroothash.EventsFromCometBFT(txs[idx], tmHeight, rs.Events)
		if err != nil {
			return nil, err
		}
		for _, e := range roothashEvents {
			result.Events = append(result.Events, &results.Event{RootHash: e})
		}

		// Transaction governance events.
		governanceEvents, err := tmgovernance.EventsFromCometBFT(txs[idx], tmHeight, rs.Events)
		if err != nil {
			return nil, err
		}
		for _, e := range governanceEvents {
			result.Events = append(result.Events, &results.Event{Governance: e})
		}

		txResults = append(txResults, result)
	}

	return &consensusAPI.TransactionsWithResults{
		Transactions: txs,
		Results:      txResults,
	}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetTransactionsWithProofs(ctx context.Context, height int64) (*consensusAPI.TransactionsWithProofs, error) {
	txs, err := n.GetTransactions(ctx, height)
	if err != nil {
		return nil, err
	}

	// CometBFT Merkle tree is computed over hashes and not over transactions.
	hashes := make([][]byte, 0, len(txs))
	for _, tx := range txs {
		hash := sha256.Sum256(tx)
		hashes = append(hashes, hash[:])
	}

	_, proofs := cmtmerkle.ProofsFromByteSlices(hashes)
	rawProofs := make([][]byte, 0, len(proofs))
	for _, p := range proofs {
		rawProofs = append(rawProofs, cbor.Marshal(p))
	}

	return &consensusAPI.TransactionsWithProofs{
		Transactions: txs,
		Proofs:       rawProofs,
	}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) State() syncer.ReadSyncer {
	return n.mux.State().Storage()
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetParameters(ctx context.Context, height int64) (*consensusAPI.Parameters, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	// Ensure all queries use the same height if the specified height is the latest.
	tmHeight, err := n.heightToCometBFTHeight(height)
	if err != nil {
		return nil, err
	}
	// Query consensus parameters directly from the state store, as fetching
	// via n.client.ConsensusParameters also tries fetching latest uncommitted
	// block which wont work with the archive node setup.
	consensusParams, err := n.stateStore.LoadConsensusParams(tmHeight)
	if err != nil {
		return nil, fmt.Errorf("%w: cometbft: consensus params query failed: %s", consensusAPI.ErrVersionNotFound, err.Error())
	}
	cpPB := consensusParams.ToProto()
	meta, err := cpPB.Marshal()
	if err != nil {
		return nil, fmt.Errorf("cometbft: failed to marshal consensus params: %w", err)
	}

	q, err := n.querier.QueryAt(ctx, tmHeight)
	if err != nil {
		return nil, fmt.Errorf("cometbft: failed to create consensus query: %w", err)
	}
	cp, err := q.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("cometbft: failed to fetch core consensus parameters: %w", err)
	}

	return &consensusAPI.Parameters{
		Height:     tmHeight,
		Parameters: *cp,
		Meta:       meta,
	}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	status := &consensusAPI.Status{
		Version:       version.ConsensusProtocol,
		Backend:       api.BackendName,
		ChainContext:  n.chainContext,
		GenesisHeight: n.genesisHeight,
	}

	if n.started() {
		// Only attempt to fetch blocks in case the consensus service has started as otherwise
		// requests will block.
		genBlk, err := n.GetBlock(ctx, n.genesisHeight)
		switch err {
		case nil:
			status.GenesisHash = genBlk.Hash
		default:
			// We may not be able to fetch the genesis block in case it has been pruned.
		}

		lastRetainedHeight, err := n.GetLastRetainedHeight(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get last retained height: %w", err)
		}
		status.LastRetainedHeight = lastRetainedHeight
		lastRetainedBlock, err := n.GetBlock(ctx, lastRetainedHeight)
		switch err {
		case nil:
			status.LastRetainedHash = lastRetainedBlock.Hash
		default:
			// Before we commit the first block, we can't load it from GetBlock. Don't give its hash in this case.
		}

		// Latest block.
		latestBlk, err := n.GetBlock(ctx, consensusAPI.HeightLatest)
		switch err {
		case nil:
			status.LatestHeight = latestBlk.Height
			status.LatestHash = latestBlk.Hash
			status.LatestTime = latestBlk.Time
			status.LatestStateRoot = latestBlk.StateRoot
			status.LatestBlockSize = latestBlk.Size

			var epoch beaconAPI.EpochTime
			epoch, err = n.beacon.GetEpoch(ctx, status.LatestHeight)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch epoch: %w", err)
			}
			status.LatestEpoch = epoch
		case consensusAPI.ErrNoCommittedBlocks:
			// No committed blocks yet.
		default:
			return nil, fmt.Errorf("failed to fetch current block: %w", err)
		}

		// Check if the local node is in the validator set for the latest (uncommitted) block.
		valSetHeight := status.LatestHeight + 1
		if valSetHeight < status.GenesisHeight {
			valSetHeight = status.GenesisHeight
		}
		vals, err := n.stateStore.LoadValidators(valSetHeight)
		if err != nil {
			// Failed to load validator set.
			status.IsValidator = false
		} else {
			consensusPk := n.identity.ConsensusSigner.Public()
			consensusAddr := []byte(crypto.PublicKeyToCometBFT(&consensusPk).Address())
			status.IsValidator = vals.HasAddress(consensusAddr)
		}
	}

	return status, nil
}

// Unimplemented methods.

// Implements consensusAPI.Backend.
func (n *commonNode) WatchCometBFTBlocks() (<-chan *cmttypes.Block, *pubsub.Subscription, error) {
	return nil, nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetNextBlockState(context.Context) (*consensusAPI.NextBlockState, error) {
	return nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmitEvidence(context.Context, *consensusAPI.Evidence) error {
	return consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmitTx(context.Context, *transaction.SignedTransaction) error {
	return consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmitTxNoWait(context.Context, *transaction.SignedTransaction) error {
	return consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmitTxWithProof(context.Context, *transaction.SignedTransaction) (*transaction.Proof, error) {
	return nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetUnconfirmedTransactions(context.Context) ([][]byte, error) {
	return nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) WatchBlocks(context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	return nil, nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmissionManager() consensusAPI.SubmissionManager {
	return &consensusAPI.NoOpSubmissionManager{}
}

// Implements consensusAPI.Backend.
func (n *commonNode) RegisterP2PService(p2pAPI.Service) error {
	return consensusAPI.ErrUnsupported
}

func newCommonNode(ctx context.Context, cfg CommonConfig) *commonNode {
	return &commonNode{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("cometbft"),
		ctx:                   ctx,
		identity:              cfg.Identity,
		rpcCtx:                &cmtrpctypes.Context{},
		dataDir:               cfg.DataDir,
		chainID:               cfg.ChainID,
		chainContext:          cfg.ChainContext,
		genesis:               cfg.Genesis,
		genesisDoc:            cfg.GenesisDoc,
		genesisHeight:         cfg.GenesisHeight,
		baseEpoch:             cfg.BaseEpoch,
		baseHeight:            cfg.BaseHeight,
		publicKeyBlacklist:    cfg.PublicKeyBlacklist,
		svcMgr:                cmbackground.NewServiceManager(logging.GetLogger("cometbft/servicemanager")),
		dbCloser:              db.NewCloser(),
		startedCh:             make(chan struct{}),
	}
}
