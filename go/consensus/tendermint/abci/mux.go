// Package abci implements the tendermint ABCI application integration.
package abci

import (
	"context"
	"encoding/hex"
	"fmt"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/prometheus/client_golang/prometheus"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	// StateKeyGenesisDigest is the state key where the genesis digest
	// aka chain context is stored.
	StateKeyGenesisDigest = "OasisGenesisDigest"

	stateKeyInitChainEvents = "OasisInitChainEvents"

	metricsUpdateInterval = 10 * time.Second

	// LogEventABCIStateSyncComplete is a log event value that signals an ABCI state syncing
	// completed event.
	LogEventABCIStateSyncComplete = "tendermint/abci/state_sync_complete"
)

var (
	abciSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_abci_db_size",
			Help: "Total size of the ABCI database (MiB).",
		},
	)
	abciCollectors = []prometheus.Collector{
		abciSize,
	}

	metricsOnce sync.Once
)

// ApplicationConfig is the configuration for the consensus application.
type ApplicationConfig struct { // nolint: maligned
	DataDir        string
	StorageBackend string
	Pruning        PruneConfig
	HaltEpoch      beacon.EpochTime
	HaltHeight     uint64
	MinGasPrice    uint64

	DisableCheckpointer       bool
	CheckpointerCheckInterval time.Duration

	// OwnTxSigner is the transaction signer identity of the local node.
	OwnTxSigner signature.PublicKey

	// MemoryOnlyStorage forces in-memory storage to be used for the state storage.
	MemoryOnlyStorage bool

	// ReadOnlyStorage forces read-only access for the state storage.
	ReadOnlyStorage bool

	// InitialHeight is the height of the initial block.
	InitialHeight uint64

	// ChainContext is the chain context for the network.
	ChainContext string
}

// ApplicationServer implements a tendermint ABCI application + socket server,
// that multiplexes multiple Oasis-specific "applications".
type ApplicationServer struct {
	mux         *abciMux
	quitChannel chan struct{}
	cleanupOnce sync.Once
}

// Start starts the ApplicationServer.
func (a *ApplicationServer) Start() error {
	if a.mux.state.timeSource == nil {
		return fmt.Errorf("mux: timeSource not defined")
	}
	if err := a.mux.checkDependencies(); err != nil {
		return err
	}
	return a.mux.finishInitialization()
}

// Stop stops the ApplicationServer.
func (a *ApplicationServer) Stop() {
	close(a.quitChannel)
}

// Quit returns a channel which is closed when the ApplicationServer is
// stopped.
func (a *ApplicationServer) Quit() <-chan struct{} {
	return a.quitChannel
}

// Cleanup cleans up the state of an ApplicationServer instance.
func (a *ApplicationServer) Cleanup() {
	a.cleanupOnce.Do(func() {
		a.mux.doCleanup()
	})
}

// Mux retrieve the abci Mux (or tendermint application) served by this server.
func (a *ApplicationServer) Mux() types.Application {
	return a.mux
}

// Register registers an Oasis application with the ABCI multiplexer.
//
// All registration must be done before Start is called.  ABCI operations
// that act on every single app (InitChain, BeginBlock, EndBlock) will be
// called in name lexicographic order. Checks that applications named in
// deps are already registered.
func (a *ApplicationServer) Register(app api.Application) error {
	return a.mux.doRegister(app)
}

// RegisterHaltHook registers a function to be called when the
// consensus Halt epoch height is reached.
func (a *ApplicationServer) RegisterHaltHook(hook consensus.HaltHook) {
	a.mux.registerHaltHook(hook)
}

// SetEpochtime sets the mux epochtime.
//
// Epochtime must be set before the multiplexer can be used.
func (a *ApplicationServer) SetEpochtime(epochTime beacon.Backend) error {
	if a.mux.state.timeSource != nil {
		return fmt.Errorf("mux: epochtime already configured")
	}

	a.mux.state.timeSource = epochTime
	return nil
}

// SetTransactionAuthHandler configures the transaction auth handler for the
// ABCI multiplexer.
func (a *ApplicationServer) SetTransactionAuthHandler(handler api.TransactionAuthHandler) error {
	if a.mux.state.txAuthHandler != nil {
		return fmt.Errorf("mux: transaction fee handler already configured")
	}

	a.mux.state.txAuthHandler = handler
	return nil
}

// TransactionAuthHandler returns the configured handler for authenticating
// transactions.
func (a *ApplicationServer) TransactionAuthHandler() api.TransactionAuthHandler {
	return a.mux.state.txAuthHandler
}

// WatchInvalidatedTx adds a watcher for when/if the transaction with given
// hash becomes invalid due to a failed re-check.
func (a *ApplicationServer) WatchInvalidatedTx(txHash hash.Hash) (<-chan error, pubsub.ClosableSubscription, error) {
	return a.mux.watchInvalidatedTx(txHash)
}

// EstimateGas calculates the amount of gas required to execute the given transaction.
func (a *ApplicationServer) EstimateGas(caller signature.PublicKey, tx *transaction.Transaction) (transaction.Gas, error) {
	return a.mux.EstimateGas(caller, tx)
}

// State returns the application state.
func (a *ApplicationServer) State() api.ApplicationQueryState {
	return a.mux.state
}

// Pruner returns the state pruner.
func (a *ApplicationServer) Pruner() api.StatePruner {
	return a.mux.state.statePruner
}

// NewApplicationServer returns a new ApplicationServer, using the provided
// directory to persist state.
func NewApplicationServer(ctx context.Context, upgrader upgrade.Backend, cfg *ApplicationConfig) (*ApplicationServer, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(abciCollectors...)
	})

	mux, err := newABCIMux(ctx, upgrader, cfg)
	if err != nil {
		return nil, err
	}

	return &ApplicationServer{
		mux:         mux,
		quitChannel: make(chan struct{}),
	}, nil
}

type abciMux struct {
	sync.RWMutex
	types.BaseApplication

	logger *logging.Logger
	state  *applicationState

	appsByName     map[string]api.Application
	appsByMethod   map[transaction.MethodName]api.Application
	appsByLexOrder []api.Application
	appBlessed     api.Application

	haltOnce  sync.Once
	haltHooks []consensus.HaltHook

	// invalidatedTxs maps transaction hashes (hash.Hash) to a subscriber
	// waiting for that transaction to become invalid.
	invalidatedTxs sync.Map

	md messageDispatcher
}

type invalidatedTxSubscription struct {
	mux      *abciMux
	txHash   hash.Hash
	resultCh chan<- error
}

func (s *invalidatedTxSubscription) Close() {
	if s.mux == nil {
		return
	}
	s.mux.invalidatedTxs.Delete(s.txHash)
	s.mux = nil
}

func (mux *abciMux) watchInvalidatedTx(txHash hash.Hash) (<-chan error, pubsub.ClosableSubscription, error) {
	resultCh := make(chan error, 1)
	sub := &invalidatedTxSubscription{
		mux:      mux,
		txHash:   txHash,
		resultCh: resultCh,
	}

	if _, exists := mux.invalidatedTxs.LoadOrStore(txHash, sub); exists {
		return nil, nil, consensus.ErrDuplicateTx
	}

	return resultCh, sub, nil
}

func (mux *abciMux) registerHaltHook(hook consensus.HaltHook) {
	mux.Lock()
	defer mux.Unlock()

	mux.haltHooks = append(mux.haltHooks, hook)
}

func (mux *abciMux) Info(req types.RequestInfo) types.ResponseInfo {
	return types.ResponseInfo{
		AppVersion:       version.TendermintAppVersion,
		LastBlockHeight:  mux.state.BlockHeight(),
		LastBlockAppHash: mux.state.StateRootHash(),
	}
}

func (mux *abciMux) InitChain(req types.RequestInitChain) types.ResponseInitChain {
	mux.logger.Debug("InitChain",
		"req", req,
	)

	// Sanity-check the genesis application state.
	st, err := parseGenesisAppState(req)
	if err != nil {
		mux.logger.Error("failed to unmarshal genesis application state",
			"err", err,
		)
		panic("mux: invalid genesis application state")
	}

	// Reset block context -- we don't really have a block but we need the time.
	mux.state.blockLock.Lock()
	mux.state.blockTime = st.Time
	mux.state.blockCtx = api.NewBlockContext(api.BlockInfo{
		Time: st.Time,
	})
	mux.state.blockLock.Unlock()

	if st.Height != req.InitialHeight || uint64(st.Height) != mux.state.initialHeight {
		panic(fmt.Errorf("mux: inconsistent initial height (genesis: %d abci: %d state: %d)", st.Height, req.InitialHeight, mux.state.initialHeight))
	}

	// Stick the digest of the genesis document into the state.
	//
	// This serves to keep bad things from happening if absolutely
	// nothing writes to the state till the Commit() call, along with
	// clearly separating chain instances based on the initialization
	// state, forever.
	chainContext := st.ChainContext()
	err = mux.state.canonicalState.Insert(mux.state.ctx, []byte(StateKeyGenesisDigest), []byte(chainContext))
	if err != nil {
		panic(err)
	}

	resp := mux.BaseApplication.InitChain(req)

	// HACK: The state is only updated iff validators or consensus parameters
	// are returned.
	//
	// See: tendermint/consensus/replay.go (Handshaker.ReplayBlocks)
	if len(resp.Validators) == 0 && resp.ConsensusParams == nil {
		resp.ConsensusParams = req.ConsensusParams
	}

	// Call InitChain() on all applications.
	mux.logger.Debug("InitChain: initializing applications")

	ctx := mux.state.NewContext(api.ContextInitChain)
	defer ctx.Close()

	for _, app := range mux.appsByLexOrder {
		mux.logger.Debug("InitChain: calling InitChain on application",
			"app", app.Name(),
		)

		if err = app.InitChain(ctx, req, st); err != nil {
			mux.logger.Error("InitChain: fatal error in application",
				"err", err,
				"app", app.Name(),
			)
			panic("mux: InitChain: fatal error in application: '" + app.Name() + "': " + err.Error())
		}
	}

	events := ctx.GetEvents()
	mux.logger.Debug("InitChain: initializing of applications complete", "num_collected_events", len(events))

	// Since returning emitted events doesn't work for InitChain() response yet,
	// we store those and return them in BeginBlock().
	evBinary := cbor.Marshal(events)
	err = ctx.State().Insert(ctx, []byte(stateKeyInitChainEvents), evBinary)
	if err != nil {
		panic(err)
	}

	// Initialize consensus parameters.
	state := abciState.NewMutableState(ctx.State())
	if err = state.SetConsensusParameters(ctx, &st.Consensus.Parameters); err != nil {
		panic(fmt.Errorf("mux: failed to set consensus parameters: %w", err))
	}
	// Since InitChain does not have a commit step, perform some state updates here.
	if err = mux.state.doInitChain(); err != nil {
		panic(fmt.Errorf("mux: failed to init chain state: %w", err))
	}

	// Set application state hash. We cannot use BlockHash as we are below initial height.
	resp.AppHash = mux.state.stateRoot.Hash[:]

	return resp
}

func (mux *abciMux) PrepareProposal(req types.RequestPrepareProposal) types.ResponsePrepareProposal {
	mux.logger.Debug("PrepareProposal",
		"height", req.Height,
	)

	// Prepare a header based on the proposal.
	header := cmtproto.Header{
		Height:             req.Height,
		Time:               req.Time,
		ProposerAddress:    req.ProposerAddress,
		NextValidatorsHash: req.NextValidatorsHash,
	}

	// Convert extended commit info to regular commit info.
	lastCommit := types.CommitInfo{
		Round: req.LocalLastCommit.Round,
		Votes: make([]types.VoteInfo, 0, len(req.LocalLastCommit.Votes)),
	}
	for _, ev := range req.LocalLastCommit.Votes {
		lastCommit.Votes = append(lastCommit.Votes, types.VoteInfo{
			Validator:       ev.Validator,
			SignedLastBlock: ev.SignedLastBlock,
		})
	}

	// Schedule an initial set of transactions.
	txs := make([][]byte, 0, len(req.Txs))
	var totalBytes int64
	for _, tx := range req.Txs {
		totalBytes += int64(len(tx))
		if totalBytes > req.MaxTxBytes {
			break
		}
		txs = append(txs, tx)
	}

	// Execute the proposal.
	defer func() {
		switch err := recover(); err {
		case nil:
			return
		case upgrade.ErrStopForUpgrade:
			// The node should stop for upgrade, propagate.
			mux.logger.Warn("node should stop for upgrade, not proposing")

			panic(err)
		default:
			// Prepare an empty proposal on panic.
			mux.logger.Error("failed to prepare proposal",
				"height", req.Height,
				"err", err,
				"stack", string(debug.Stack()),
			)
		}

		// Force re-execution of the proposal.
		mux.state.resetProposal()
	}()
	if err := mux.executeProposal([]byte{}, header, txs, lastCommit, req.Misbehavior); err != nil {
		mux.logger.Error("failed to prepare proposal",
			"height", req.Height,
			"err", err,
		)
		return types.ResponsePrepareProposal{}
	}

	// Record proposal inputs so we can compare in ProcessProposal.
	p := mux.state.proposal
	p.header = &header
	p.txs = txs
	p.misbehavior = req.Misbehavior

	return types.ResponsePrepareProposal{Txs: txs}
}

func (mux *abciMux) ProcessProposal(req types.RequestProcessProposal) (resp types.ResponseProcessProposal) {
	mux.logger.Debug("ProcessProposal",
		"height", req.Height,
		"hash", hex.EncodeToString(req.Hash),
	)

	// Prepare a header based on the proposal.
	header := cmtproto.Header{
		Height:             req.Height,
		Time:               req.Time,
		ProposerAddress:    req.ProposerAddress,
		NextValidatorsHash: req.NextValidatorsHash,
	}

	// If the proposal has already been executed (e.g. because we are the proposer), accept.
	if mux.state.proposal != nil && !mux.state.proposal.needsExecution() && mux.state.proposal.isEqual(&header, req.Txs, req.Misbehavior) {
		mux.logger.Debug("reusing own executed proposal")
		mux.state.proposal.hash = req.Hash // Was not known in prepare phase.

		return types.ResponseProcessProposal{
			Status: types.ResponseProcessProposal_ACCEPT,
		}
	}

	// Execute the proposal.
	defer func() {
		switch err := recover(); err {
		case nil:
			return
		case upgrade.ErrStopForUpgrade:
			// The node should stop for upgrade. Propagate.
			mux.logger.Warn("node should stop for upgrade, not processing proposal")

			panic(err)
		default:
			// Reject proposal on panic.
			mux.logger.Error("failed to process proposal",
				"height", req.Height,
				"err", err,
				"stack", string(debug.Stack()),
			)

			resp = types.ResponseProcessProposal{
				Status: types.ResponseProcessProposal_REJECT,
			}
		}

		// Force re-execution of the proposal.
		mux.state.resetProposal()
	}()
	if err := mux.executeProposal(req.Hash, header, req.Txs, req.ProposedLastCommit, req.Misbehavior); err != nil {
		mux.logger.Error("failed to process proposal",
			"height", req.Height,
			"err", err,
		)
		return types.ResponseProcessProposal{
			Status: types.ResponseProcessProposal_REJECT,
		}
	}

	return types.ResponseProcessProposal{
		Status: types.ResponseProcessProposal_ACCEPT,
	}
}

func (mux *abciMux) executeProposal(
	hash []byte,
	header cmtproto.Header,
	txs [][]byte,
	lastCommit types.CommitInfo,
	misbehavior []types.Misbehavior,
) error {
	// Reset proposal state.
	mux.state.resetProposal()
	mux.state.proposal.hash = hash

	resultsBeginBlock := mux.BeginBlock(types.RequestBeginBlock{
		Hash:                hash,
		Header:              header,
		LastCommitInfo:      lastCommit,
		ByzantineValidators: misbehavior,
	})

	resultsDeliverTx := make([]*types.ResponseDeliverTx, 0, len(txs))
	for _, tx := range txs {
		resp := mux.DeliverTx(types.RequestDeliverTx{
			Tx: tx,
		})
		resultsDeliverTx = append(resultsDeliverTx, &resp)
	}

	resultsEndBlock := mux.EndBlock(types.RequestEndBlock{
		Height: header.Height,
	})

	// Update the proposal with results, marking the proposal as executed.
	mux.state.proposal.setResults(&resultsBeginBlock, resultsDeliverTx, &resultsEndBlock)

	return nil
}

func (mux *abciMux) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	// Use cached results when available, otherwise reset proposal.
	if !mux.state.resetProposalIfChanged(req.Hash) && !mux.state.proposal.needsExecution() {
		return *mux.state.proposal.resultsBeginBlock
	}

	blockHeight := mux.state.BlockHeight()

	mux.logger.Debug("BeginBlock",
		"req", req,
		"hash", hex.EncodeToString(req.Hash),
		"block_height", blockHeight,
	)

	params := mux.state.ConsensusParameters()

	// Reset block context for the new block.
	blockCtx := api.NewBlockContext(api.BlockInfo{
		Time:                 req.Header.Time,
		ProposerAddress:      req.Header.ProposerAddress,
		LastCommitInfo:       req.LastCommitInfo,
		ValidatorMisbehavior: req.ByzantineValidators,
	})
	if params.MaxBlockGas > 0 {
		blockCtx.GasAccountant = api.NewGasAccountant(params.MaxBlockGas)
	} else {
		blockCtx.GasAccountant = api.NewNopGasAccountant()
	}
	mux.state.blockCtx = blockCtx

	// Create BeginBlock context.
	ctx := mux.state.NewContext(api.ContextBeginBlock)
	defer ctx.Close()

	currentEpoch, err := mux.state.GetCurrentEpoch(ctx)
	if err != nil {
		panic(fmt.Errorf("mux: can't get current epoch in BeginBlock: %w", err))
	}

	// Check if there are any upgrades pending or if we need to halt for an upgrade. Note that these
	// checks must run on each block to make sure that any pending upgrade descriptors are cleared
	// after consensus upgrade is performed.
	if upgrader := mux.state.Upgrader(); upgrader != nil {
		switch err := upgrader.ConsensusUpgrade(ctx, currentEpoch, blockHeight); err {
		case nil:
			// Everything ok.
		case upgrade.ErrStopForUpgrade:
			// Signal graceful stop for upgrade.
			mux.haltForUpgrade(blockHeight, currentEpoch, true)
		default:
			panic(fmt.Errorf("mux: error while trying to perform consensus upgrade: %w", err))
		}
	}

	// Check if we need to halt based on local configuration.
	if mux.state.shouldLocalHalt(blockHeight+1, currentEpoch) {
		mux.haltForUpgrade(blockHeight, currentEpoch, true)
	}

	// Dispatch BeginBlock to all applications.
	for _, app := range mux.appsByLexOrder {
		if err := app.BeginBlock(ctx); err != nil {
			mux.logger.Error("BeginBlock: fatal error in application",
				"err", err,
				"app", app.Name(),
			)

			if errors.Is(err, upgrade.ErrStopForUpgrade) {
				mux.haltForUpgrade(blockHeight, currentEpoch, true)
			}
			panic(fmt.Errorf("mux: BeginBlock: fatal error in application: '%s': %w", app.Name(), err))
		}
	}

	response := mux.BaseApplication.BeginBlock(req)

	// Collect and return events from the application's BeginBlock calls.
	response.Events = ctx.GetEvents()

	// During the first block, also collect and prepend application events
	// generated during InitChain to BeginBlock events.
	if mux.state.BlockHeight() == 0 {
		evBinary, err := ctx.State().Get(ctx, []byte(stateKeyInitChainEvents))
		if err != nil {
			panic(fmt.Errorf("mux: BeginBlock: failed to query init chain events: %w", err))
		}
		if evBinary != nil {
			var events []types.Event
			_ = cbor.Unmarshal(evBinary, &events)

			response.Events = append(events, response.Events...)

			if err := ctx.State().Remove(ctx, []byte(stateKeyInitChainEvents)); err != nil {
				panic(fmt.Errorf("mux: BeginBlock: failed to remove init chain events: %w", err))
			}
		}
	}

	return response
}

func (mux *abciMux) notifyInvalidatedCheckTx(txHash hash.Hash, err error) {
	if item, exists := mux.invalidatedTxs.Load(txHash); exists {
		// Notify subscriber.
		sub := item.(*invalidatedTxSubscription)
		sub.resultCh <- err
		close(sub.resultCh)

		mux.invalidatedTxs.Delete(txHash)
	}
}

func (mux *abciMux) CheckTx(req types.RequestCheckTx) types.ResponseCheckTx {
	ctx := mux.state.NewContext(api.ContextCheckTx)
	defer ctx.Close()

	if err := mux.executeTx(ctx, req.Tx); err != nil {
		module, code := errors.Code(err)

		if req.Type == types.CheckTxType_Recheck {
			// This is a re-check and the transaction just failed validation. Since
			// the mempool provides no way of getting notified when a previously
			// valid transaction becomes invalid, handle this here.

			// XXX: The Tendermint mempool should have provisions for this instead
			//      of us hacking our way through this here.
			txHash := hash.NewFromBytes(req.Tx)

			mux.notifyInvalidatedCheckTx(txHash, err)
		}

		return types.ResponseCheckTx{
			Codespace: module,
			Code:      code,
			Log:       err.Error(),
			GasWanted: int64(ctx.Gas().GasWanted()),
			GasUsed:   int64(ctx.Gas().GasUsed()),
		}
	}

	return types.ResponseCheckTx{
		Code:      types.CodeTypeOK,
		GasWanted: int64(ctx.Gas().GasWanted()),
		GasUsed:   int64(ctx.Gas().GasUsed()),
		Priority:  ctx.GetPriority(),
	}
}

func (mux *abciMux) DeliverTx(req types.RequestDeliverTx) types.ResponseDeliverTx {
	// Use cached results when available.
	if !mux.state.proposal.needsExecution() {
		if len(mux.state.proposal.resultsDeliverTx) == 0 {
			panic(fmt.Errorf("mux: corrupted transaction execution results"))
		}

		resp := mux.state.proposal.resultsDeliverTx[0]
		mux.state.proposal.resultsDeliverTx = mux.state.proposal.resultsDeliverTx[1:]
		return *resp
	}

	ctx := mux.state.NewContext(api.ContextDeliverTx)
	defer ctx.Close()

	if err := mux.executeTx(ctx, req.Tx); err != nil {
		if api.IsUnavailableStateError(err) {
			// Make sure to not commit any transactions which include results based on unavailable
			// and/or corrupted state -- doing so can further corrupt state.
			ctx.Logger().Error("unavailable and/or corrupted state detected during tx processing",
				"err", err,
			)
			panic(err)
		}
		module, code := errors.Code(err)

		return types.ResponseDeliverTx{
			Codespace: module,
			Code:      code,
			Log:       err.Error(),
			Events:    ctx.GetEvents(),
			GasWanted: int64(ctx.Gas().GasWanted()),
			GasUsed:   int64(ctx.Gas().GasUsed()),
		}
	}

	return types.ResponseDeliverTx{
		Code:      types.CodeTypeOK,
		Data:      cbor.Marshal(ctx.Data()),
		Events:    ctx.GetEvents(),
		GasWanted: int64(ctx.Gas().GasWanted()),
		GasUsed:   int64(ctx.Gas().GasUsed()),
	}
}

func (mux *abciMux) EndBlock(req types.RequestEndBlock) types.ResponseEndBlock {
	// Use cached results when available.
	if !mux.state.proposal.needsExecution() {
		if len(mux.state.proposal.resultsDeliverTx) != 0 {
			panic(fmt.Errorf("mux: corrupted transaction execution results"))
		}

		return *mux.state.proposal.resultsEndBlock
	}

	mux.logger.Debug("EndBlock",
		"req", req,
		"block_height", mux.state.BlockHeight(),
	)

	ctx := mux.state.NewContext(api.ContextEndBlock)
	defer ctx.Close()

	// Dispatch EndBlock to all applications.
	resp := mux.BaseApplication.EndBlock(req)
	for _, app := range mux.appsByLexOrder {
		newResp, err := app.EndBlock(ctx)
		if err != nil {
			mux.logger.Error("EndBlock: fatal error in application",
				"err", err,
				"app", app.Name(),
			)
			panic(fmt.Errorf("mux: EndBlock: fatal error in application: '%s': %w", app.Name(), err))
		}
		if app.Blessed() {
			resp = newResp
		}
	}

	// Run any EndBlock upgrade handlers when there is an upgrade.
	if upgrader := mux.state.Upgrader(); upgrader != nil {
		currentEpoch, err := mux.state.GetCurrentEpoch(ctx)
		if err != nil {
			panic(fmt.Errorf("mux: can't get current epoch in BeginBlock: %w", err))
		}

		err = upgrader.ConsensusUpgrade(ctx, currentEpoch, ctx.BlockHeight())
		// This should never fail as all the checks were already performed in BeginBlock.
		if err != nil {
			panic(fmt.Errorf("mux: error while trying to perform consensus upgrade: %w", err))
		}
	}

	// Update tags.
	resp.Events = ctx.GetEvents()

	// Update version to what we are actually running.
	resp.ConsensusParamUpdates = &cmtproto.ConsensusParams{
		Version: &cmtproto.VersionParams{
			App: version.TendermintAppVersion,
		},
	}

	return resp
}

func (mux *abciMux) Commit() types.ResponseCommit {
	lastRetainedVersion, err := mux.state.doCommit()
	if err != nil {
		mux.logger.Error("Commit failed",
			"err", err,
		)

		// There appears to be no way to indicate to the caller that
		// this failed.
		panic(err)
	}

	mux.logger.Debug("Commit",
		"block_height", mux.state.BlockHeight(),
		"state_root_hash", hex.EncodeToString(mux.state.StateRootHash()),
		"last_retained_version", lastRetainedVersion,
	)

	// Check if there is an upgrade pending for the next consensus block. This is needed because
	// validators will halt before proposing a block so there will be no "next block" until all of
	// the validators upgrade, but we also want non-validator nodes to halt for upgrade.
	mux.maybeHaltForUpgrade()

	return types.ResponseCommit{
		Data:         mux.state.StateRootHash(),
		RetainHeight: int64(lastRetainedVersion),
	}
}

func (mux *abciMux) doCleanup() {
	mux.state.doCleanup()

	for _, v := range mux.appsByLexOrder {
		v.OnCleanup()
	}
}

func (mux *abciMux) doRegister(app api.Application) error {
	name := app.Name()
	if mux.appsByName[name] != nil {
		return fmt.Errorf("mux: application already registered: '%s'", name)
	}
	if app.Blessed() {
		// Enforce the 1 blessed app limitation.
		if mux.appBlessed != nil {
			return fmt.Errorf("mux: blessed application already exists")
		}
		mux.appBlessed = app
	}

	mux.appsByName[name] = app
	for _, m := range app.Methods() {
		if _, exists := mux.appsByMethod[m]; exists {
			return fmt.Errorf("mux: method already registered: %s", m)
		}
		mux.appsByMethod[m] = app
	}
	mux.rebuildAppLexOrdering() // Inefficient but not a lot of apps.

	app.OnRegister(mux.state, &mux.md)
	mux.logger.Debug("Registered new application",
		"app", app.Name(),
	)

	return nil
}

func (mux *abciMux) rebuildAppLexOrdering() {
	numApps := len(mux.appsByName)
	appOrder := make([]string, 0, numApps)
	for name := range mux.appsByName {
		appOrder = append(appOrder, name)
	}
	sort.Strings(appOrder)

	mux.appsByLexOrder = make([]api.Application, 0, numApps)
	for _, name := range appOrder {
		mux.appsByLexOrder = append(mux.appsByLexOrder, mux.appsByName[name])
	}
}

func (mux *abciMux) checkDependencies() error {
	var missingDeps [][2]string
	for neededFor, app := range mux.appsByName {
		for _, dep := range app.Dependencies() {
			if _, ok := mux.appsByName[dep]; !ok {
				missingDeps = append(missingDeps, [2]string{dep, neededFor})
			}
		}
	}
	if missingDeps != nil {
		return fmt.Errorf("mux: missing dependencies %v", missingDeps)
	}
	return nil
}

func (mux *abciMux) finishInitialization() error {
	if mux.state.BlockHeight() >= mux.state.InitialHeight() {
		mux.state.resetProposal()
		defer mux.state.closeProposal()

		// Notify applications that state has been synced. This is used to make sure that things
		// like pending upgrade descriptors are refreshed immediately.
		ctx := mux.state.NewContext(api.ContextEndBlock)
		defer ctx.Close()

		if _, err := mux.md.Publish(ctx, api.MessageStateSyncCompleted, nil); err != nil {
			mux.logger.Error("failed to dispatch state sync completed message",
				"err", err,
			)
			return err
		}
	}

	// Start the state pruner. This is done here instead of on creation of the state to allow for
	// any consensus services and runtimes to be registered first as they can register prune
	// handlers that can prevent pruning of certain versions.
	if err := mux.state.startPruner(); err != nil {
		return fmt.Errorf("failed to start pruner: %w", err)
	}

	return nil
}

func newABCIMux(ctx context.Context, upgrader upgrade.Backend, cfg *ApplicationConfig) (*abciMux, error) {
	state, err := newApplicationState(ctx, upgrader, cfg)
	if err != nil {
		return nil, err
	}

	// Ensure that if state is initialized it matches the genesis file. There could be a discrepancy
	// in case someone copied over the state from one network but is using a genesis file from
	// another.
	chainContext, err := state.canonicalState.Get(ctx, []byte(StateKeyGenesisDigest))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chain context from state: %w", err)
	}
	if len(chainContext) > 0 && string(chainContext) != cfg.ChainContext {
		return nil, fmt.Errorf("state chain context does not match genesis file (genesis: %s state: %s)",
			cfg.ChainContext,
			string(chainContext),
		)
	}

	mux := &abciMux{
		logger:       logging.GetLogger("abci-mux"),
		state:        state,
		appsByName:   make(map[string]api.Application),
		appsByMethod: make(map[transaction.MethodName]api.Application),
	}

	mux.logger.Debug("ABCI multiplexer initialized",
		"block_height", state.BlockHeight(),
		"state_root_hash", hex.EncodeToString(state.StateRootHash()),
	)

	return mux, nil
}
