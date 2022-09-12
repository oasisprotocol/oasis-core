package full

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/spf13/viper"
	tmcore "github.com/tendermint/tendermint/rpc/core"
	tmcoretypes "github.com/tendermint/tendermint/rpc/core/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	"github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/store"
	tmtypes "github.com/tendermint/tendermint/types"
	tmdb "github.com/tendermint/tm-db"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	cmservice "github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/supplementarysanity"
	tmbeacon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/beacon"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/db"
	tmgovernance "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/governance"
	tmkeymanager "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/keymanager"
	tmregistry "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/registry"
	tmroothash "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/roothash"
	tmscheduler "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/scheduler"
	tmstaking "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/staking"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governanceAPI "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanagerAPI "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmbackground "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/registry"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	schedulerAPI "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// commonNode implements the common tendermint node functionality shared between
// full and archive nodes.
type commonNode struct {
	sync.Mutex
	cmservice.BaseBackgroundService

	svcMgr *cmbackground.ServiceManager

	serviceClients   []api.ServiceClient
	serviceClientsWg sync.WaitGroup

	ctx    context.Context
	rpcCtx *tmrpctypes.Context

	dataDir  string
	identity *identity.Identity

	genesis *genesisAPI.Document

	mux *abci.ApplicationServer

	beacon     beaconAPI.Backend
	governance governanceAPI.Backend
	keymanager keymanagerAPI.Backend
	registry   registryAPI.Backend
	roothash   roothashAPI.Backend
	scheduler  schedulerAPI.Backend
	staking    stakingAPI.Backend

	// These stores must be populated by the parent before the node is deemed ready.
	blockStoreDB tmdb.DB
	stateStore   state.Store
	dbCloser     *db.Closer

	state     uint32
	startedCh chan struct{}

	parentNode api.Backend
}

// Possible internal node states.
const (
	stateNotReady    = 0
	stateInitialized = 1
	stateStarted     = 2
	stateStopping    = 3
)

func (n *commonNode) initialized() bool {
	return atomic.LoadUint32(&n.state) >= stateInitialized
}

func (n *commonNode) started() bool {
	return atomic.LoadUint32(&n.state) >= stateStarted
}

func (n *commonNode) ensureStarted(ctx context.Context) error {
	// Make sure that the Tendermint service is setup and started.
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
		return fmt.Errorf("tendermint/common_node: not in initialized state")
	}

	if err := n.mux.Start(); err != nil {
		return err
	}

	return nil
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
	for _, v := range n.genesis.Consensus.Parameters.PublicKeyBlacklist {
		if err := v.Blacklist(); err != nil {
			n.Logger.Error("initialize: failed to blacklist key",
				"err", err,
				"pk", v,
			)
			return err
		}
	}

	// Initialize the beacon/epochtime backend.
	var (
		err error

		scBeacon tmbeacon.ServiceClient
	)
	if scBeacon, err = tmbeacon.New(n.ctx, n.parentNode); err != nil {
		n.Logger.Error("initialize: failed to initialize beapoch backend",
			"err", err,
		)
		return err
	}
	n.beacon = scBeacon
	n.serviceClients = append(n.serviceClients, scBeacon)
	if err = n.mux.SetEpochtime(n.beacon); err != nil {
		return err
	}

	// Initialize the rest of backends.
	var scKeyManager tmkeymanager.ServiceClient
	if scKeyManager, err = tmkeymanager.New(n.ctx, n.parentNode); err != nil {
		n.Logger.Error("initialize: failed to initialize keymanager backend",
			"err", err,
		)
		return err
	}
	n.keymanager = scKeyManager
	n.serviceClients = append(n.serviceClients, scKeyManager)

	var scRegistry tmregistry.ServiceClient
	if scRegistry, err = tmregistry.New(n.ctx, n.parentNode); err != nil {
		n.Logger.Error("initialize: failed to initialize registry backend",
			"err", err,
		)
		return err
	}
	n.registry = scRegistry
	if cmmetrics.Enabled() {
		n.svcMgr.RegisterCleanupOnly(registry.NewMetricsUpdater(n.ctx, n.registry), "registry metrics updater")
	}
	n.serviceClients = append(n.serviceClients, scRegistry)
	n.svcMgr.RegisterCleanupOnly(n.registry, "registry backend")

	var scStaking tmstaking.ServiceClient
	if scStaking, err = tmstaking.New(n.ctx, n.parentNode); err != nil {
		n.Logger.Error("staking: failed to initialize staking backend",
			"err", err,
		)
		return err
	}
	n.staking = scStaking
	n.serviceClients = append(n.serviceClients, scStaking)
	n.svcMgr.RegisterCleanupOnly(n.staking, "staking backend")

	var scScheduler tmscheduler.ServiceClient
	if scScheduler, err = tmscheduler.New(n.ctx, n.parentNode); err != nil {
		n.Logger.Error("scheduler: failed to initialize scheduler backend",
			"err", err,
		)
		return err
	}
	n.scheduler = scScheduler
	n.serviceClients = append(n.serviceClients, scScheduler)
	n.svcMgr.RegisterCleanupOnly(n.scheduler, "scheduler backend")

	var scRootHash tmroothash.ServiceClient
	if scRootHash, err = tmroothash.New(n.ctx, n.dataDir, n.parentNode); err != nil {
		n.Logger.Error("roothash: failed to initialize roothash backend",
			"err", err,
		)
		return err
	}
	n.roothash = scRootHash
	n.serviceClients = append(n.serviceClients, scRootHash)
	n.svcMgr.RegisterCleanupOnly(n.roothash, "roothash backend")

	var scGovernance tmgovernance.ServiceClient
	if scGovernance, err = tmgovernance.New(n.ctx, n.parentNode); err != nil {
		n.Logger.Error("governance: failed to initialize governance backend",
			"err", err,
		)
		return err
	}
	n.governance = scGovernance
	n.serviceClients = append(n.serviceClients, scGovernance)
	n.svcMgr.RegisterCleanupOnly(n.governance, "governance backend")

	// Enable supplementary sanity checks when enabled.
	if viper.GetBool(CfgSupplementarySanityEnabled) {
		ssa := supplementarysanity.New(viper.GetUint64(CfgSupplementarySanityInterval))
		if err = n.RegisterApplication(ssa); err != nil {
			return fmt.Errorf("failed to register supplementary sanity check app: %w", err)
		}
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
func (n *commonNode) ConsensusKey() signature.PublicKey {
	return n.identity.ConsensusSigner.Public()
}

// Implements consensusAPI.Backend.
func (n *commonNode) SupportedFeatures() consensusAPI.FeatureMask {
	return consensusAPI.FeatureServices | consensusAPI.FeatureFullNode
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetAddresses() ([]node.ConsensusAddress, error) {
	u, err := common.GetExternalAddress()
	if err != nil {
		return nil, err
	}

	var addr node.ConsensusAddress
	if err = addr.Address.UnmarshalText([]byte(u.Host)); err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address host: %w", err)
	}
	addr.ID = n.identity.P2PSigner.Public()

	return []node.ConsensusAddress{addr}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) Checkpointer() checkpoint.Checkpointer {
	return n.mux.State().Checkpointer()
}

// Implements consensusAPI.Backend.
func (n *commonNode) StateToGenesis(ctx context.Context, blockHeight int64) (*genesisAPI.Document, error) {
	blk, err := n.GetTendermintBlock(ctx, blockHeight)
	if err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, consensusAPI.ErrNoCommittedBlocks
	}
	blockHeight = blk.Header.Height

	// Get initial genesis doc.
	genesisDoc, err := n.GetGenesisDocument(ctx)
	if err != nil {
		return nil, err
	}

	// Call StateToGenesis on all backends and merge the results together.
	beaconGenesis, err := n.Beacon().StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

	registryGenesis, err := n.Registry().StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

	roothashGenesis, err := n.RootHash().StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

	stakingGenesis, err := n.Staking().StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

	keymanagerGenesis, err := n.KeyManager().StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

	schedulerGenesis, err := n.Scheduler().StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

	governanceGenesis, err := n.Governance().StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

	return &genesisAPI.Document{
		Height:     blockHeight,
		ChainID:    genesisDoc.ChainID,
		HaltEpoch:  genesisDoc.HaltEpoch,
		Time:       blk.Header.Time,
		Beacon:     *beaconGenesis,
		Registry:   *registryGenesis,
		RootHash:   *roothashGenesis,
		Staking:    *stakingGenesis,
		Governance: *governanceGenesis,
		KeyManager: *keymanagerGenesis,
		Scheduler:  *schedulerGenesis,
		Consensus:  genesisDoc.Consensus,
	}, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetGenesisDocument(ctx context.Context) (*genesisAPI.Document, error) {
	return n.genesis, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetChainContext(ctx context.Context) (string, error) {
	return n.genesis.ChainContext(), nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) Beacon() beaconAPI.Backend {
	return n.beacon
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
func (n *commonNode) RegisterApplication(app api.Application) error {
	return n.mux.Register(app)
}

// Implements consensusAPI.Backend.
func (n *commonNode) SetTransactionAuthHandler(handler api.TransactionAuthHandler) error {
	return n.mux.SetTransactionAuthHandler(handler)
}

// Implements consensusAPI.Backend.
func (n *commonNode) TransactionAuthHandler() consensusAPI.TransactionAuthHandler {
	return n.mux.TransactionAuthHandler()
}

// Implements consensusAPI.Backend.
func (n *commonNode) EstimateGas(ctx context.Context, req *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	return n.mux.EstimateGas(req.Signer, req.Transaction)
}

// Implements consensusAPI.Backend.
func (n *commonNode) Pruner() api.StatePruner {
	return n.mux.Pruner()
}

// Implements consensusAPI.Backend.
func (n *commonNode) RegisterHaltHook(hook consensusAPI.HaltHook) {
	if !n.initialized() {
		return
	}

	n.mux.RegisterHaltHook(hook)
}

func (n *commonNode) heightToTendermintHeight(height int64) (int64, error) {
	var tmHeight int64
	if height == consensusAPI.HeightLatest {
		// Do not let Tendermint determine the latest height (e.g., by passing nil) as that
		// completely ignores ABCI processing so it can return a block for which local state does
		// not yet exist. Use our mux notion of latest height instead.
		tmHeight = n.mux.State().BlockHeight()
		if tmHeight == 0 {
			// No committed blocks yet.
			return 0, consensusAPI.ErrNoCommittedBlocks
		}
	} else {
		tmHeight = height
	}

	return tmHeight, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetSignerNonce(ctx context.Context, req *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	return n.mux.TransactionAuthHandler().GetSignerNonce(ctx, req)
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetTendermintBlock(ctx context.Context, height int64) (*tmtypes.Block, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := n.heightToTendermintHeight(height)
	switch err {
	case nil:
		// Continues bellow.
	case consensusAPI.ErrNoCommittedBlocks:
		// No committed blocks yet.
		return nil, nil
	default:
		return nil, err
	}
	result, err := tmcore.Block(n.rpcCtx, &tmHeight)
	if err != nil {
		return nil, fmt.Errorf("tendermint: block query failed: %w", err)
	}
	return result.Block, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetBlockResults(ctx context.Context, height int64) (*tmcoretypes.ResultBlockResults, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return nil, err
	}

	tmHeight, err := n.heightToTendermintHeight(height)
	if err != nil {
		return nil, err
	}
	result, err := tmcore.BlockResults(n.rpcCtx, &tmHeight)
	if err != nil {
		return nil, fmt.Errorf("tendermint: block results query failed: %w", err)
	}

	return result, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetLastRetainedVersion(ctx context.Context) (int64, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return -1, err
	}
	state := store.LoadBlockStoreState(n.blockStoreDB)
	return state.Base, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetBlock(ctx context.Context, height int64) (*consensusAPI.Block, error) {
	blk, err := n.GetTendermintBlock(ctx, height)
	if err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, consensusAPI.ErrNoCommittedBlocks
	}

	return api.NewBlock(blk), nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	blk, err := n.GetTendermintBlock(ctx, height)
	if err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, consensusAPI.ErrNoCommittedBlocks
	}

	txs := make([][]byte, 0, len(blk.Data.Txs))
	for _, v := range blk.Data.Txs {
		txs = append(txs, v[:])
	}
	return txs, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetTransactionsWithResults(ctx context.Context, height int64) (*consensusAPI.TransactionsWithResults, error) {
	var txsWithResults consensusAPI.TransactionsWithResults

	blk, err := n.GetTendermintBlock(ctx, height)
	if err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, consensusAPI.ErrNoCommittedBlocks
	}
	for _, tx := range blk.Data.Txs {
		txsWithResults.Transactions = append(txsWithResults.Transactions, tx[:])
	}

	res, err := n.GetBlockResults(ctx, blk.Height)
	if err != nil {
		return nil, err
	}
	for txIdx, rs := range res.TxsResults {
		// Transaction result.
		result := &results.Result{
			Error: results.Error{
				Module:  rs.GetCodespace(),
				Code:    rs.GetCode(),
				Message: rs.GetLog(),
			},
		}

		// Transaction staking events.
		stakingEvents, err := tmstaking.EventsFromTendermint(
			txsWithResults.Transactions[txIdx],
			blk.Height,
			rs.Events,
		)
		if err != nil {
			return nil, err
		}
		for _, e := range stakingEvents {
			result.Events = append(result.Events, &results.Event{Staking: e})
		}

		// Transaction registry events.
		registryEvents, _, err := tmregistry.EventsFromTendermint(
			txsWithResults.Transactions[txIdx],
			blk.Height,
			rs.Events,
		)
		if err != nil {
			return nil, err
		}
		for _, e := range registryEvents {
			result.Events = append(result.Events, &results.Event{Registry: e})
		}

		// Transaction roothash events.
		roothashEvents, err := tmroothash.EventsFromTendermint(
			txsWithResults.Transactions[txIdx],
			blk.Height,
			rs.Events,
		)
		if err != nil {
			return nil, err
		}
		for _, e := range roothashEvents {
			result.Events = append(result.Events, &results.Event{RootHash: e})
		}

		// Transaction governance events.
		governanceEvents, err := tmgovernance.EventsFromTendermint(
			txsWithResults.Transactions[txIdx],
			blk.Height,
			rs.Events,
		)
		if err != nil {
			return nil, err
		}
		for _, e := range governanceEvents {
			result.Events = append(result.Events, &results.Event{Governance: e})
		}

		txsWithResults.Results = append(txsWithResults.Results, result)
	}
	return &txsWithResults, nil
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	status := &consensusAPI.Status{
		Version:  version.ConsensusProtocol,
		Backend:  api.BackendName,
		Features: n.SupportedFeatures(),
	}

	status.ChainContext = n.genesis.ChainContext()
	status.GenesisHeight = n.genesis.Height
	if n.started() {
		// Only attempt to fetch blocks in case the consensus service has started as otherwise
		// requests will block.
		genBlk, err := n.GetBlock(ctx, n.genesis.Height)
		switch err {
		case nil:
			status.GenesisHash = genBlk.Hash
		default:
			// We may not be able to fetch the genesis block in case it has been pruned.
		}

		lastRetainedHeight, err := n.GetLastRetainedVersion(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get last retained height: %w", err)
		}
		// Some pruning configurations return 0 instead of a valid block height. Clamp those to the genesis height.
		if lastRetainedHeight < n.genesis.Height {
			lastRetainedHeight = n.genesis.Height
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
			consensusAddr := []byte(crypto.PublicKeyToTendermint(&consensusPk).Address())
			status.IsValidator = vals.HasAddress(consensusAddr)
		}
	}

	return status, nil
}

// Unimplemented methods.

// Implements consensusAPI.Backend.
func (n *commonNode) WatchTendermintBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription, error) {
	return nil, nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetNextBlockState(ctx context.Context) (*consensusAPI.NextBlockState, error) {
	return nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmitEvidence(ctx context.Context, evidence *consensusAPI.Evidence) error {
	return consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	return consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmitTxWithProof(ctx context.Context, tx *transaction.SignedTransaction) (*transaction.Proof, error) {
	return nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	return nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) WatchBlocks(ctx context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	return nil, nil, consensusAPI.ErrUnsupported
}

// Implements consensusAPI.Backend.
func (n *commonNode) SubmissionManager() consensusAPI.SubmissionManager {
	return &consensusAPI.NoOpSubmissionManager{}
}

func newCommonNode(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	genesisProvider genesisAPI.Provider,
) (*commonNode, error) {
	// Retrieve the genesis document early so that it is possible to
	// use it while initializing other things.
	genesisDoc, err := genesisProvider.GetGenesisDocument()
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to get genesis doc: %w", err)
	}

	// Make sure that the consensus backend specified in the genesis
	// document is the correct one.
	if genesisDoc.Consensus.Backend != api.BackendName {
		return nil, fmt.Errorf("tendermint: genesis document contains incorrect consensus backend: %s",
			genesisDoc.Consensus.Backend,
		)
	}

	return &commonNode{
		BaseBackgroundService: *cmservice.NewBaseBackgroundService("tendermint"),
		ctx:                   ctx,
		identity:              identity,
		rpcCtx:                &tmrpctypes.Context{},
		genesis:               genesisDoc,
		dataDir:               dataDir,
		svcMgr:                cmbackground.NewServiceManager(logging.GetLogger("tendermint/servicemanager")),
		dbCloser:              db.NewCloser(),
		startedCh:             make(chan struct{}),
	}, nil
}
