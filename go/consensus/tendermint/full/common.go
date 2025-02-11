package full

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"

	"github.com/spf13/viper"
	tmcore "github.com/tendermint/tendermint/rpc/core"
	tmcoretypes "github.com/tendermint/tendermint/rpc/core/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
	tmstate "github.com/tendermint/tendermint/state"
	"github.com/tendermint/tendermint/store"
	tmtypes "github.com/tendermint/tendermint/types"
	tmdb "github.com/tendermint/tm-db"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
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
	tmcommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	tmepochtime "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/epochtime"
	tmkeymanager "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/keymanager"
	tmregistry "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/registry"
	tmroothash "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/roothash"
	tmscheduler "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/scheduler"
	tmstaking "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/staking"
	epochtimeAPI "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	keymanagerAPI "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmbackground "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/registry"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
	schedulerAPI "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
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
	epochtime  epochtimeAPI.Backend
	keymanager keymanagerAPI.Backend
	registry   registryAPI.Backend
	roothash   roothashAPI.Backend
	scheduler  schedulerAPI.Backend
	staking    stakingAPI.Backend

	blockStoreDB tmdb.DB
	stateStore   tmdb.DB

	// Guarded by the lock.
	isStarted, isInitialized bool

	startedCh chan struct{}

	parentNode api.Backend
}

func (n *commonNode) initialized() bool {
	n.Lock()
	defer n.Unlock()

	return n.isInitialized
}

func (n *commonNode) started() bool {
	n.Lock()
	defer n.Unlock()

	return n.isStarted
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

	return nil
}

func (n *commonNode) Start() error {
	n.Lock()
	defer n.Unlock()

	if n.isStarted {
		return fmt.Errorf("tendermint/common_node: already started")
	}

	if !n.isInitialized {
		return fmt.Errorf("tendermint/common_node: not initialized")
	}

	if err := n.mux.Start(); err != nil {
		return err
	}

	n.isStarted = true
	close(n.startedCh)

	return nil
}

func (n *commonNode) Stop() {
	n.Lock()
	defer n.Unlock()

	if !n.isStarted || !n.isInitialized {
		return
	}

	n.svcMgr.Stop()
	n.mux.Stop()
	if err := n.blockStoreDB.Close(); err != nil {
		n.Logger.Error("error on stopping block store", "err", err)
	}
	if err := n.stateStore.Close(); err != nil {
		n.Logger.Error("error on stopping state store", "err", err)
	}
}

func (n *commonNode) initialize() error {
	n.Lock()
	defer n.Unlock()

	if n.isInitialized {
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

		scEpochTime tmepochtime.ServiceClient
		scBeacon    tmbeacon.ServiceClient
	)

	scEpochTime, err = tmepochtime.New(n.ctx, n.parentNode, n.genesis.EpochTime.Parameters.Interval)
	if err != nil {
		n.Logger.Error("initEpochtime: failed to initialize epochtime backend",
			"err", err,
		)
		return err
	}
	n.epochtime = scEpochTime
	n.serviceClients = append(n.serviceClients, scEpochTime)
	if err := n.mux.SetEpochtime(n.epochtime); err != nil {
		return err
	}

	if scBeacon, err = tmbeacon.New(n.ctx, n.parentNode); err != nil {
		n.Logger.Error("initialize: failed to initialize beapoch backend",
			"err", err,
		)
		return err
	}
	n.beacon = scBeacon
	n.serviceClients = append(n.serviceClients, scBeacon)

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

	// Enable supplementary sanity checks when enabled.
	if viper.GetBool(CfgSupplementarySanityEnabled) {
		ssa := supplementarysanity.New(viper.GetUint64(CfgSupplementarySanityInterval))
		if err = n.RegisterApplication(ssa); err != nil {
			return fmt.Errorf("failed to register supplementary sanity check app: %w", err)
		}
	}

	n.isInitialized = true

	return nil
}

// Implements service.BackgroundService.
func (n *commonNode) Cleanup() {
	n.serviceClientsWg.Wait()
	n.svcMgr.Cleanup()
}

func (t *commonNode) ConsensusKey() signature.PublicKey {
	return t.identity.ConsensusSigner.Public()
}

func (n *commonNode) SupportedFeatures() consensusAPI.FeatureMask {
	return consensusAPI.FeatureServices | consensusAPI.FeatureFullNode
}

func (n *commonNode) GetAddresses() ([]node.ConsensusAddress, error) {
	addrURI := viper.GetString(cfgCoreExternalAddress)
	if addrURI == "" {
		addrURI = viper.GetString(tmcommon.CfgCoreListenAddress)
	}
	if addrURI == "" {
		return nil, fmt.Errorf("tendermint: no external address configured")
	}
	u, err := url.Parse(addrURI)
	if err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address URL: %w", err)
	}
	if u.Scheme != "tcp" {
		return nil, fmt.Errorf("tendermint: external address has invalid scheme: '%v'", u.Scheme)
	}

	if u.Hostname() == "0.0.0.0" {
		var port string
		if _, port, err = net.SplitHostPort(u.Host); err != nil {
			return nil, fmt.Errorf("tendermint: malformed external address host/port: %w", err)
		}

		ip := common.GuessExternalAddress()
		if ip == nil {
			return nil, fmt.Errorf("tendermint: failed to guess external address")
		}

		u.Host = ip.String() + ":" + port
	}

	var addr node.ConsensusAddress
	if err = addr.Address.UnmarshalText([]byte(u.Host)); err != nil {
		return nil, fmt.Errorf("tendermint: failed to parse external address host: %w", err)
	}
	addr.ID = n.identity.P2PSigner.Public()

	return []node.ConsensusAddress{addr}, nil
}

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
	epochtimeGenesis, err := n.epochtime.StateToGenesis(ctx, blockHeight)
	if err != nil {
		return nil, err
	}

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

	return &genesisAPI.Document{
		Height:     blockHeight,
		ChainID:    genesisDoc.ChainID,
		HaltEpoch:  genesisDoc.HaltEpoch,
		Time:       blk.Header.Time,
		EpochTime:  *epochtimeGenesis,
		Beacon:     *beaconGenesis,
		Registry:   *registryGenesis,
		RootHash:   *roothashGenesis,
		Staking:    *stakingGenesis,
		KeyManager: *keymanagerGenesis,
		Scheduler:  *schedulerGenesis,
		Consensus:  genesisDoc.Consensus,
	}, nil
}

func (n *commonNode) GetGenesisDocument(ctx context.Context) (*genesisAPI.Document, error) {
	return n.genesis, nil
}

func (n *commonNode) GetChainContext(ctx context.Context) (string, error) {
	return n.genesis.ChainContext(), nil
}

func (n *commonNode) EpochTime() epochtimeAPI.Backend {
	return n.epochtime
}

func (n *commonNode) Beacon() beaconAPI.Backend {
	return n.beacon
}

func (n *commonNode) KeyManager() keymanagerAPI.Backend {
	return n.keymanager
}

func (n *commonNode) Registry() registryAPI.Backend {
	return n.registry
}

func (n *commonNode) RootHash() roothashAPI.Backend {
	return n.roothash
}

func (n *commonNode) Staking() stakingAPI.Backend {
	return n.staking
}

func (n *commonNode) Scheduler() schedulerAPI.Backend {
	return n.scheduler
}

func (n *commonNode) RegisterApplication(app api.Application) error {
	return n.mux.Register(app)
}

func (n *commonNode) SetTransactionAuthHandler(handler api.TransactionAuthHandler) error {
	return n.mux.SetTransactionAuthHandler(handler)
}

func (n *commonNode) TransactionAuthHandler() consensusAPI.TransactionAuthHandler {
	return n.mux.TransactionAuthHandler()
}

func (n *commonNode) EstimateGas(ctx context.Context, req *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	return n.mux.EstimateGas(req.Signer, req.Transaction)
}

func (n *commonNode) RegisterHaltHook(hook func(context.Context, int64, epochtimeAPI.EpochTime)) {
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

func (n *commonNode) GetSignerNonce(ctx context.Context, req *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	return n.mux.TransactionAuthHandler().GetSignerNonce(ctx, req)
}

// These method need to be provided.
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

func (n *commonNode) GetBlockResults(height int64) (*tmcoretypes.ResultBlockResults, error) {
	if err := n.ensureStarted(n.ctx); err != nil {
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

func (n *commonNode) GetLastRetainedVersion(ctx context.Context) (int64, error) {
	if err := n.ensureStarted(ctx); err != nil {
		return -1, err
	}
	state := store.LoadBlockStoreState(n.blockStoreDB)
	return state.Base, nil
}

// Following use the provided methods.
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

func (n *commonNode) GetEpoch(ctx context.Context, height int64) (epochtimeAPI.EpochTime, error) {
	if n.epochtime == nil {
		return epochtimeAPI.EpochInvalid, consensusAPI.ErrUnsupported
	}
	return n.epochtime.GetEpoch(ctx, height)
}

func (n *commonNode) WaitEpoch(ctx context.Context, epoch epochtimeAPI.EpochTime) error {
	if n.epochtime == nil {
		return consensusAPI.ErrUnsupported
	}

	ch, sub := n.epochtime.WatchEpochs()
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-ch:
			if !ok {
				return context.Canceled
			}
			if e >= epoch {
				return nil
			}
		}
	}
}

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

	res, err := n.GetBlockResults(blk.Height)
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

		txsWithResults.Results = append(txsWithResults.Results, result)
	}
	return &txsWithResults, nil
}

func (n *commonNode) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	status := &consensusAPI.Status{
		ConsensusVersion: version.ConsensusProtocol.String(),
		Backend:          api.BackendName,
		Features:         n.SupportedFeatures(),
	}

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
		vals, err := tmstate.LoadValidators(n.stateStore, valSetHeight)
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

func (n *commonNode) WatchTendermintBlocks() (<-chan *tmtypes.Block, *pubsub.Subscription, error) {
	return nil, nil, consensusAPI.ErrUnsupported
}

// Implements Backend.
func (n *commonNode) SubmitEvidence(ctx context.Context, evidence *consensusAPI.Evidence) error {
	return consensusAPI.ErrUnsupported
}

// Implements Backend.
func (n *commonNode) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	return consensusAPI.ErrUnsupported
}

// Implements Backend.
func (n *commonNode) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	return nil, consensusAPI.ErrUnsupported
}

// Implements Backend.
func (n *commonNode) WatchBlocks(ctx context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	return nil, nil, consensusAPI.ErrUnsupported
}

// Implements Backend.
func (n *commonNode) SubmissionManager() consensusAPI.SubmissionManager {
	return &consensusAPI.NoOpSubmissionManager{}
}
