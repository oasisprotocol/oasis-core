// Package abci implements the tendermint ABCI application integration.
package abci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tendermint/tendermint/abci/types"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"

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
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	abciState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/abci/state"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	// StateKeyGenesisDigest is the state key where the genesis digest
	// aka chain context is stored.
	StateKeyGenesisDigest = "OasisGenesisDigest"

	stateKeyInitChainEvents = "OasisInitChainEvents"

	metricsUpdateInterval = 10 * time.Second

	blockHeightInvalid = -1

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
	DataDir         string
	StorageBackend  string
	Pruning         PruneConfig
	HaltEpochHeight beacon.EpochTime
	MinGasPrice     uint64

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

	lastBeginBlock int64
	currentTime    time.Time

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
		LastBlockAppHash: mux.state.BlockHash(),
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

	mux.currentTime = st.Time

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
	err = mux.state.deliverTxTree.Insert(mux.state.ctx, []byte(StateKeyGenesisDigest), []byte(chainContext))
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

	ctx := mux.state.NewContext(api.ContextInitChain, mux.currentTime)
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

	mux.logger.Debug("InitChain: initializing of applications complete", "num_collected_events", len(ctx.GetEvents()))

	// Since returning emitted events doesn't work for InitChain() response yet,
	// we store those and return them in BeginBlock().
	evBinary := cbor.Marshal(ctx.GetEvents())
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
	if err = mux.state.doInitChain(st.Time); err != nil {
		panic(fmt.Errorf("mux: failed to init chain state: %w", err))
	}

	// Set application state hash. We cannot use BlockHash as we are below initial height.
	resp.AppHash = mux.state.stateRoot.Hash[:]

	return resp
}

func (mux *abciMux) dispatchHaltHooks(blockHeight int64, currentEpoch beacon.EpochTime, err error) {
	for _, hook := range mux.haltHooks {
		hook(mux.state.ctx, blockHeight, currentEpoch, err)
	}
	mux.logger.Debug("halt hook dispatch complete")
}

func (mux *abciMux) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	blockHeight := mux.state.BlockHeight()

	mux.logger.Debug("BeginBlock",
		"req", req,
		"block_height", blockHeight,
	)

	// 99% sure this is a protocol violation.
	if mux.lastBeginBlock == blockHeight {
		panic(fmt.Errorf("mux: redundant BeginBlock"))
	}
	defer func() {
		atomic.StoreInt64(&mux.lastBeginBlock, blockHeight)
	}()
	mux.currentTime = req.Header.Time

	params := mux.state.ConsensusParameters()

	// Create empty block context.
	mux.state.blockCtx = api.NewBlockContext()
	if params.MaxBlockGas > 0 {
		mux.state.blockCtx.Set(api.GasAccountantKey{}, api.NewGasAccountant(params.MaxBlockGas))
	} else {
		mux.state.blockCtx.Set(api.GasAccountantKey{}, api.NewNopGasAccountant())
	}
	mux.state.blockCtx.Set(api.BlockProposerKey{}, req.Header.ProposerAddress)
	// Create BeginBlock context.
	ctx := mux.state.NewContext(api.ContextBeginBlock, mux.currentTime)
	defer ctx.Close()

	currentEpoch, err := mux.state.GetCurrentEpoch(ctx)
	if err != nil {
		panic(fmt.Errorf("mux: can't get current epoch in BeginBlock: %w", err))
	}

	// Check if there are any upgrades pending or if we need to halt for an upgrade. Note that these
	// checks must run on each block to make sure that any pending upgrade descriptors are cleared
	// after consensus upgrade is performed.
	if upgrader := mux.state.Upgrader(); upgrader != nil {
		switch err := upgrader.ConsensusUpgrade(ctx, currentEpoch, ctx.BlockHeight()); err {
		case nil:
			// Everything ok.
		case upgrade.ErrStopForUpgrade:
			// Signal graceful stop for upgrade.
			mux.logger.Debug("dispatching halt hooks for upgrade")
			mux.dispatchHaltHooks(blockHeight, currentEpoch, err)
			panic(err)
		default:
			panic(fmt.Errorf("mux: error while trying to perform consensus upgrade: %w", err))
		}
	}

	switch mux.state.haltMode {
	case false:
		if !mux.state.inHaltEpoch(ctx) {
			break
		}
		// On transition, trigger halt hooks.
		mux.logger.Info("BeginBlock: halt mode transition, emitting empty block",
			"block_height", blockHeight,
			"epoch", mux.state.haltEpochHeight,
		)
		mux.logger.Debug("dispatching halt hooks before halt epoch")
		mux.dispatchHaltHooks(blockHeight, currentEpoch, nil)
		return types.ResponseBeginBlock{}
	case true:
		// After one block into the halt epoch, terminate.
		mux.logger.Info("BeginBlock: after halt epoch, halting",
			"block_height", blockHeight,
		)
		// XXX: there is no way to stop tendermint consensus other than
		// triggering a panic. Once possible, we should stop the consensus
		// layer here and gracefully shutdown the node.
		panic("tendermint: after halt epoch, halting")
	}

	// Dispatch BeginBlock to all applications.
	for _, app := range mux.appsByLexOrder {
		if err := app.BeginBlock(ctx, req); err != nil {
			mux.logger.Error("BeginBlock: fatal error in application",
				"err", err,
				"app", app.Name(),
			)

			mux.logger.Debug("dispatching halt hooks on begin block failure")
			mux.dispatchHaltHooks(blockHeight, currentEpoch, err)

			panic(fmt.Errorf("mux: BeginBlock: fatal error in application: '%s': %w", app.Name(), err))
		}
	}

	response := mux.BaseApplication.BeginBlock(req)

	// Collect and return events from the application's BeginBlock calls.
	response.Events = ctx.GetEvents()

	// During the first block, also collect and prepend application events
	// generated during InitChain to BeginBlock events.
	if mux.state.BlockHeight() == 0 {
		evBinary, err := mux.state.deliverTxTree.Get(ctx, []byte(stateKeyInitChainEvents))
		if err != nil {
			panic(fmt.Errorf("mux: BeginBlock: failed to query init chain events: %w", err))
		}
		if evBinary != nil {
			var events []types.Event
			_ = cbor.Unmarshal(evBinary, &events)

			response.Events = append(events, response.Events...)

			if err := mux.state.deliverTxTree.Remove(ctx, []byte(stateKeyInitChainEvents)); err != nil {
				panic(fmt.Errorf("mux: BeginBlock: failed to remove init chain events: %w", err))
			}
		}
	}

	return response
}

func (mux *abciMux) decodeTx(ctx *api.Context, rawTx []byte) (*transaction.Transaction, *transaction.SignedTransaction, error) {
	if mux.state.haltMode {
		ctx.Logger().Debug("executeTx: in halt, rejecting all transactions")
		return nil, nil, fmt.Errorf("halt mode, rejecting all transactions")
	}

	params := mux.state.ConsensusParameters()
	if params.MaxTxSize > 0 && uint64(len(rawTx)) > params.MaxTxSize {
		// This deliberately avoids logging the rawTx since spamming the
		// logs is also bad.
		ctx.Logger().Error("received oversized transaction",
			"tx_size", len(rawTx),
		)
		return nil, nil, consensus.ErrOversizedTx
	}

	// Unmarshal envelope and verify transaction.
	var sigTx transaction.SignedTransaction
	if err := cbor.Unmarshal(rawTx, &sigTx); err != nil {
		ctx.Logger().Error("failed to unmarshal signed transaction",
			"tx", base64.StdEncoding.EncodeToString(rawTx),
		)
		return nil, nil, err
	}
	var tx transaction.Transaction
	if err := sigTx.Open(&tx); err != nil {
		ctx.Logger().Error("failed to verify transaction signature",
			"tx", base64.StdEncoding.EncodeToString(rawTx),
		)
		return nil, nil, err
	}
	if err := tx.SanityCheck(); err != nil {
		ctx.Logger().Error("bad transaction",
			"tx", base64.StdEncoding.EncodeToString(rawTx),
		)
		return nil, nil, err
	}

	return &tx, &sigTx, nil
}

func (mux *abciMux) processTx(ctx *api.Context, tx *transaction.Transaction, txSize int) error {
	// Lookup method handler.
	app := mux.appsByMethod[tx.Method]
	if app == nil {
		ctx.Logger().Error("unknown method",
			"tx", tx,
			"method", tx.Method,
		)
		return fmt.Errorf("mux: unknown method: %s", tx.Method)
	}

	// Pass the transaction through the fee handler if configured.
	//
	// Ignore fees for critical protocol methods to ensure they are processed in a block. Note that
	// this relies on method handlers to prevent DoS.
	if txAuthHandler := mux.state.txAuthHandler; txAuthHandler != nil && !tx.Method.IsCritical() {
		if err := txAuthHandler.AuthenticateTx(ctx, tx); err != nil {
			ctx.Logger().Debug("failed to authenticate transaction (pre-execute)",
				"tx", tx,
				"tx_signer", ctx.TxSigner(),
				"method", tx.Method,
				"err", err,
			)
			return err
		}
	}

	// Charge gas based on the size of the transaction.
	params := mux.state.ConsensusParameters()
	if err := ctx.Gas().UseGas(txSize, consensusGenesis.GasOpTxByte, params.GasCosts); err != nil {
		return err
	}

	// Route to correct handler.
	ctx.Logger().Debug("dispatching",
		"app", app.Name(),
		"tx", tx,
	)

	if err := app.ExecuteTx(ctx, tx); err != nil {
		return err
	}

	//  Pass the transaction through the PostExecuteTx handler if configured.
	if txAuthHandler := mux.state.txAuthHandler; txAuthHandler != nil {
		if err := txAuthHandler.PostExecuteTx(ctx, tx); err != nil {
			ctx.Logger().Debug("failed to authenticate transaction (post-execute)",
				"tx", tx,
				"tx_signer", ctx.TxSigner(),
				"method", tx.Method,
				"err", err,
			)
			return err
		}
	}

	return nil
}

func (mux *abciMux) executeTx(ctx *api.Context, rawTx []byte) error {
	tx, sigTx, err := mux.decodeTx(ctx, rawTx)
	if err != nil {
		return err
	}

	// Set authenticated transaction signer.
	ctx.SetTxSigner(sigTx.Signature.PublicKey)

	// If we are in CheckTx mode and there is a pending upgrade in this block, make sure to reject
	// any transactions before processing as they may potentially query incompatible state.
	if upgrader := mux.state.Upgrader(); upgrader != nil && ctx.IsCheckOnly() {
		hasUpgrade, err := upgrader.HasPendingUpgradeAt(ctx, ctx.BlockHeight()+1)
		if err != nil {
			return fmt.Errorf("failed to check for pending upgrades: %w", err)
		}
		if hasUpgrade {
			return transaction.ErrUpgradePending
		}
	}

	return mux.processTx(ctx, tx, len(rawTx))
}

func (mux *abciMux) EstimateGas(caller signature.PublicKey, tx *transaction.Transaction) (transaction.Gas, error) {
	if tx == nil {
		return 0, consensus.ErrInvalidArgument
	}

	// Certain modules, in particular the beacon require InitChain or BeginBlock
	// to have completed before initialization is complete.
	if atomic.LoadInt64(&mux.lastBeginBlock) == blockHeightInvalid {
		return 0, consensus.ErrNoCommittedBlocks
	}

	// As opposed to other transaction dispatch entry points (CheckTx/DeliverTx), this method can
	// be called in parallel to the consensus layer and to other invocations.
	//
	// For simulation mode, time will be filled in by NewContext from last block time.
	ctx := mux.state.NewContext(api.ContextSimulateTx, time.Time{})
	defer ctx.Close()

	// Modify transaction to include maximum possible gas in order to estimate the upper limit on
	// the serialized transaction size. For amount, use a reasonable amount (in theory the actual
	// amount could be bigger depending on the gas price).
	tx.Fee = &transaction.Fee{
		Gas: transaction.Gas(math.MaxUint64),
	}
	_ = tx.Fee.Amount.FromUint64(math.MaxUint64)

	ctx.SetTxSigner(caller)
	mockSignedTx := transaction.SignedTransaction{
		Signed: signature.Signed{
			Blob: cbor.Marshal(tx),
			// Signature is fixed-size, so we can leave it as default.
		},
	}
	txSize := len(cbor.Marshal(mockSignedTx))

	// Ignore any errors that occurred during simulation as we only need to estimate gas even if the
	// transaction seems like it will fail.
	_ = mux.processTx(ctx, tx, txSize)

	return ctx.Gas().GasUsed(), nil
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
	ctx := mux.state.NewContext(api.ContextCheckTx, mux.currentTime)
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
	}
}

func (mux *abciMux) DeliverTx(req types.RequestDeliverTx) types.ResponseDeliverTx {
	ctx := mux.state.NewContext(api.ContextDeliverTx, mux.currentTime)
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
	mux.logger.Debug("EndBlock",
		"req", req,
		"block_height", mux.state.BlockHeight(),
	)

	if mux.state.haltMode {
		mux.logger.Debug("EndBlock: in halt, emitting empty block")
		return types.ResponseEndBlock{}
	}

	ctx := mux.state.NewContext(api.ContextEndBlock, mux.currentTime)
	defer ctx.Close()

	// Dispatch EndBlock to all applications.
	resp := mux.BaseApplication.EndBlock(req)
	for _, app := range mux.appsByLexOrder {
		newResp, err := app.EndBlock(ctx, req)
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
	resp.ConsensusParamUpdates = &types.ConsensusParams{
		Version: &tmproto.VersionParams{
			AppVersion: version.TendermintAppVersion,
		},
	}

	// Clear block context.
	mux.state.blockCtx = nil

	return resp
}

func (mux *abciMux) Commit() types.ResponseCommit {
	lastRetainedVersion, err := mux.state.doCommit(mux.currentTime)
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
		"block_hash", hex.EncodeToString(mux.state.BlockHash()),
		"last_retained_version", lastRetainedVersion,
	)

	return types.ResponseCommit{
		Data:         mux.state.BlockHash(),
		RetainHeight: int64(lastRetainedVersion),
	}
}

func (mux *abciMux) ListSnapshots(req types.RequestListSnapshots) types.ResponseListSnapshots {
	// Get a list of all current checkpoints.
	cps, err := mux.state.storage.Checkpointer().GetCheckpoints(mux.state.ctx, &checkpoint.GetCheckpointsRequest{
		Version: 1,
	})
	if err != nil {
		mux.logger.Error("failed to get checkpoints",
			"err", err,
		)
		return types.ResponseListSnapshots{}
	}

	var rsp types.ResponseListSnapshots
	for _, cp := range cps {
		cpHash := cp.EncodedHash()

		rsp.Snapshots = append(rsp.Snapshots, &types.Snapshot{
			Height:   cp.Root.Version,
			Format:   uint32(cp.Version),
			Chunks:   uint32(len(cp.Chunks)),
			Hash:     cpHash[:],
			Metadata: cbor.Marshal(cp),
		})
	}

	return rsp
}

func (mux *abciMux) OfferSnapshot(req types.RequestOfferSnapshot) types.ResponseOfferSnapshot {
	if req.Snapshot == nil {
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}
	if req.Snapshot.Format != 1 {
		mux.logger.Warn("received snapshot with unsupported version",
			"version", req.Snapshot.Format,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT_FORMAT}
	}

	// Decode checkpoint metadata hash and sanity check against the request.
	var metadataHash hash.Hash
	metadataHash.FromBytes(req.Snapshot.Metadata)
	var h hash.Hash
	if err := h.UnmarshalBinary(req.Snapshot.Hash); err != nil {
		mux.logger.Warn("received snapshot with malformed hash",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}
	if !metadataHash.Equal(&h) {
		mux.logger.Warn("received snapshot with mismatching hash",
			"expected_hash", h,
			"hash", metadataHash,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}

	// Decode checkpoint metadata.
	var cp checkpoint.Metadata
	if err := cbor.Unmarshal(req.Snapshot.Metadata, &cp); err != nil {
		mux.logger.Warn("received snapshot with malformed metadata",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}

	// Number of chunks must match.
	if int(req.Snapshot.Chunks) != len(cp.Chunks) {
		mux.logger.Warn("received snapshot with mismatching number of chunks",
			"expected_chunks", len(cp.Chunks),
			"chunks", req.Snapshot.Chunks,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}
	// Root hash must match.
	var appHash hash.Hash
	if err := appHash.UnmarshalBinary(req.AppHash); err != nil {
		// NOTE: This should never happen as it indicates a problem with Tendermint.
		mux.logger.Error("received request with malformed hash",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ABORT}
	}
	if !cp.Root.Hash.Equal(&appHash) {
		mux.logger.Warn("received snapshot with mismatching root hash",
			"expected_root", appHash,
			"root", cp.Root.Hash,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_REJECT}
	}

	// Snapshot seems correct (e.g., it is for the correct root), start the restoration process.
	if err := mux.state.storage.NodeDB().StartMultipartInsert(cp.Root.Version); err != nil {
		mux.logger.Error("failed to start multipart restoration",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ABORT}
	}
	if err := mux.state.storage.Checkpointer().StartRestore(mux.state.ctx, &cp); err != nil {
		mux.logger.Error("failed to start restore",
			"err", err,
		)
		return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ABORT}
	}

	mux.logger.Info("started state restore process",
		"root", cp.Root,
	)

	return types.ResponseOfferSnapshot{Result: types.ResponseOfferSnapshot_ACCEPT}
}

func (mux *abciMux) LoadSnapshotChunk(req types.RequestLoadSnapshotChunk) types.ResponseLoadSnapshotChunk {
	// Fetch the metadata for the specified checkpoint.
	cps, err := mux.state.storage.Checkpointer().GetCheckpoints(mux.state.ctx, &checkpoint.GetCheckpointsRequest{
		Version:     uint16(req.Format),
		RootVersion: &req.Height,
	})
	if err != nil {
		mux.logger.Error("failed to get checkpoints",
			"err", err,
		)
		return types.ResponseLoadSnapshotChunk{}
	}
	if len(cps) != 1 {
		mux.logger.Error("failed to get checkpoints",
			"cps", len(cps),
		)
		return types.ResponseLoadSnapshotChunk{}
	}

	// Fetch the chunk itself.
	chunk, err := cps[0].GetChunkMetadata(uint64(req.Chunk))
	if err != nil {
		mux.logger.Error("failed to get chunk metadata",
			"err", err,
		)
		return types.ResponseLoadSnapshotChunk{}
	}
	var buf bytes.Buffer
	if err := mux.state.storage.Checkpointer().GetCheckpointChunk(mux.state.ctx, chunk, &buf); err != nil {
		mux.logger.Error("failed to get chunk",
			"err", err,
		)
		return types.ResponseLoadSnapshotChunk{}
	}

	return types.ResponseLoadSnapshotChunk{Chunk: buf.Bytes()}
}

func (mux *abciMux) ApplySnapshotChunk(req types.RequestApplySnapshotChunk) types.ResponseApplySnapshotChunk {
	cp := mux.state.storage.Checkpointer().GetCurrentCheckpoint()

	mux.logger.Debug("attempting to restore a chunk",
		"root", cp.Root,
		"index", req.Index,
	)

	buf := bytes.NewBuffer(req.Chunk)
	done, err := mux.state.storage.Checkpointer().RestoreChunk(mux.state.ctx, uint64(req.Index), buf)
	switch {
	case err == nil:
	case errors.Is(err, checkpoint.ErrNoRestoreInProgress):
		// This should never happen.
		mux.logger.Error("ApplySnapshotChunk called without OfferSnapshot, aborting state sync")
		if err = mux.state.storage.Checkpointer().AbortRestore(mux.state.ctx); err != nil {
			mux.logger.Error("failed to abort checkpoint restore: %w",
				"err", err,
			)
		}
		if err = mux.state.storage.NodeDB().AbortMultipartInsert(); err != nil {
			mux.logger.Error("failed to abort multipart restore: %w",
				"err", err,
			)
		}
		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
	case errors.Is(err, checkpoint.ErrChunkAlreadyRestored):
		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ACCEPT}
	case errors.Is(err, checkpoint.ErrChunkCorrupted):
		// Corrupted chunk, refetch.
		mux.logger.Warn("received corrupted chunk",
			"sender", req.Sender,
			"index", req.Index,
			"err", err,
		)

		return types.ResponseApplySnapshotChunk{
			RefetchChunks: []uint32{req.Index},
			// TODO: Consider banning the sender.
			Result: types.ResponseApplySnapshotChunk_RETRY,
		}
	case errors.Is(err, checkpoint.ErrChunkProofVerificationFailed):
		// Chunk was as specified in the manifest but did not match the reported root. In this case
		// we need to abort processing the given snapshot.
		mux.logger.Warn("chunk contains invalid proof, snapshot is bad",
			"err", err,
		)

		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_REJECT_SNAPSHOT}
	default:
		// Unspecified error during restoration.
		mux.logger.Error("error during chunk restoration, aborting state sync",
			"err", err,
		)
		if err = mux.state.storage.Checkpointer().AbortRestore(mux.state.ctx); err != nil {
			mux.logger.Error("failed to abort checkpoint restore: %w",
				"err", err,
			)
		}
		if err = mux.state.storage.NodeDB().AbortMultipartInsert(); err != nil {
			mux.logger.Error("failed to abort multipart restore: %w",
				"err", err,
			)
		}

		return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
	}

	// Check if we are done with the restoration. In this case, finalize the root.
	if done {
		err = mux.state.storage.NodeDB().Finalize(mux.state.ctx, []storageApi.Root{cp.Root})
		if err != nil {
			mux.logger.Error("failed to finalize restored root",
				"err", err,
			)
			if err = mux.state.storage.NodeDB().AbortMultipartInsert(); err != nil {
				mux.logger.Error("failed to abort multipart restore: %w",
					"err", err,
				)
			}
			return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
		}

		if err = mux.state.doApplyStateSync(cp.Root); err != nil {
			mux.logger.Error("failed to apply state sync root",
				"err", err,
			)
			return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
		}

		mux.logger.Info("successfully synced state",
			"root", cp.Root,
			logging.LogEvent, LogEventABCIStateSyncComplete,
		)

		// Notify applications that state has been synced.
		ctx := mux.state.NewContext(api.ContextEndBlock, mux.currentTime)
		defer ctx.Close()

		if _, err = mux.md.Publish(ctx, api.MessageStateSyncCompleted, nil); err != nil {
			mux.logger.Error("failed to dispatch state sync completed message",
				"err", err,
			)
			return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ABORT}
		}
	}

	return types.ResponseApplySnapshotChunk{Result: types.ResponseApplySnapshotChunk_ACCEPT}
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
		// Notify applications that state has been synced. This is used to make sure that things
		// like pending upgrade descriptors are refreshed immediately.
		ctx := mux.state.NewContext(api.ContextEndBlock, mux.currentTime)
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

	mux := &abciMux{
		logger:         logging.GetLogger("abci-mux"),
		state:          state,
		appsByName:     make(map[string]api.Application),
		appsByMethod:   make(map[transaction.MethodName]api.Application),
		lastBeginBlock: blockHeightInvalid,
	}

	mux.logger.Debug("ABCI multiplexer initialized",
		"block_height", state.BlockHeight(),
		"block_hash", hex.EncodeToString(state.BlockHash()),
	)

	return mux, nil
}
