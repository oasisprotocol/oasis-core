// Package abci implements the tendermint ABCI application integration.
package abci

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/version"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	upgrade "github.com/oasislabs/oasis-core/go/upgrade/api"
)

const (
	stateKeyGenesisDigest   = "OasisGenesisDigest"
	stateKeyGenesisRequest  = "OasisGenesisRequest"
	stateKeyInitChainEvents = "OasisInitChainEvents"

	metricsUpdateInterval = 10 * time.Second

	// debugTxLifetime is the transaction mempool lifetime when CheckTx is disabled (debug only).
	debugTxLifetime = 1 * time.Minute
)

var (
	abciSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_abci_db_size",
			Help: "Total size of the ABCI database (MiB)",
		},
	)
	abciCollectors = []prometheus.Collector{
		abciSize,
	}

	metricsOnce sync.Once
)

// ApplicationConfig is the configuration for the consensus application.
type ApplicationConfig struct {
	DataDir         string
	Pruning         PruneConfig
	HaltEpochHeight epochtime.EpochTime
	MinGasPrice     uint64
	DisableCheckTx  bool

	// OwnTxSigner is the transaction signer identity of the local node.
	OwnTxSigner signature.PublicKey
}

// TransactionAuthHandler is the interface for ABCI applications that handle
// authenticating transactions (checking nonces and fees).
type TransactionAuthHandler interface {
	consensus.TransactionAuthHandler

	// AuthenticateTx authenticates the given transaction by making sure
	// that the nonce is correct and deducts any fees as specified.
	//
	// It may reject the transaction in case of incorrect nonces, insufficient
	// balance to pay fees or (only during CheckTx) if the gas price is too
	// low.
	//
	// The context may be modified to configure a gas accountant.
	AuthenticateTx(ctx *Context, tx *transaction.Transaction) error
}

// Application is the interface implemented by multiplexed Oasis-specific
// ABCI applications.
type Application interface {
	// Name returns the name of the Application.
	Name() string

	// ID returns the unique identifier of the application.
	ID() uint8

	// Methods returns the list of supported methods.
	Methods() []transaction.MethodName

	// Blessed returns true iff the Application should be considered
	// "blessed", and able to alter the validation set and handle the
	// access control related standard ABCI queries.
	//
	// Only one Application instance may be Blessed per multiplexer
	// instance.
	Blessed() bool

	// Dependencies returns the names of applications that the application
	// depends on.
	Dependencies() []string

	// QueryFactory returns an application-specific query factory that
	// can be used to construct new queries at specific block heights.
	QueryFactory() interface{}

	// OnRegister is the function that is called when the Application
	// is registered with the multiplexer instance.
	OnRegister(state ApplicationState)

	// OnCleanup is the function that is called when the ApplicationServer
	// has been halted.
	OnCleanup()

	// ExecuteTx executes a transaction.
	ExecuteTx(*Context, *transaction.Transaction) error

	// ForeignExecuteTx delivers a transaction of another application for
	// processing.
	//
	// This can be used to run post-tx hooks when dependencies exist
	// between applications.
	ForeignExecuteTx(*Context, Application, *transaction.Transaction) error

	// InitChain initializes the blockchain with validators and other
	// info from TendermintCore.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	InitChain(*Context, types.RequestInitChain, *genesis.Document) error

	// BeginBlock signals the beginning of a block.
	//
	// Returned tags will be added to the current block.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	BeginBlock(*Context, types.RequestBeginBlock) error

	// EndBlock signals the end of a block, returning changes to the
	// validator set.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	EndBlock(*Context, types.RequestEndBlock) (types.ResponseEndBlock, error)

	// FireTimer is called within BeginBlock before any other processing
	// takes place for each timer that should fire.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	FireTimer(*Context, *Timer) error

	// Commit is omitted because Applications will work on a cache of
	// the state bound to the multiplexer.
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
	return a.mux.checkDependencies()
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
func (a *ApplicationServer) Register(app Application) error {
	return a.mux.doRegister(app)
}

// RegisterGenesisHook registers a function to be called when the
// consensus backend is initialized from genesis (e.g., on fresh
// start).
func (a *ApplicationServer) RegisterGenesisHook(hook func()) {
	a.mux.registerGenesisHook(hook)
}

// RegisterHaltHook registers a function to be called when the
// consensus Halt epoch height is reached.
func (a *ApplicationServer) RegisterHaltHook(hook func(ctx context.Context, blockHeight int64, epoch epochtime.EpochTime)) {
	a.mux.registerHaltHook(hook)
}

// Pruner returns the ABCI state pruner.
func (a *ApplicationServer) Pruner() StatePruner {
	return a.mux.state.statePruner
}

// SetEpochtime sets the mux epochtime.
//
// Epochtime must be set before the multiplexer can be used.
func (a *ApplicationServer) SetEpochtime(epochTime epochtime.Backend) error {
	if a.mux.state.timeSource != nil {
		return fmt.Errorf("mux: epochtime already configured")
	}

	a.mux.state.timeSource = epochTime
	return nil
}

// SetTransactionAuthHandler configures the transaction auth handler for the
// ABCI multiplexer.
func (a *ApplicationServer) SetTransactionAuthHandler(handler TransactionAuthHandler) error {
	if a.mux.state.txAuthHandler != nil {
		return fmt.Errorf("mux: transaction fee handler already configured")
	}

	a.mux.state.txAuthHandler = handler
	return nil
}

// TransactionAuthHandler returns the configured handler for authenticating
// transactions.
func (a *ApplicationServer) TransactionAuthHandler() TransactionAuthHandler {
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

	logger   *logging.Logger
	upgrader upgrade.Backend
	state    *applicationState

	appsByName     map[string]Application
	appsByMethod   map[transaction.MethodName]Application
	appsByLexOrder []Application
	appBlessed     Application

	lastBeginBlock int64
	currentTime    time.Time

	genesisHooks []func()
	haltHooks    []func(context.Context, int64, epochtime.EpochTime)

	// invalidatedTxs maps transaction hashes (hash.Hash) to a subscriber
	// waiting for that transaction to become invalid.
	invalidatedTxs sync.Map
	// debugExpiringTxs maps transaction hashes to the time at which they were created. This is only
	// used in case CheckTx is disabled (for debug purposes only).
	debugExpiringTxs map[hash.Hash]time.Time
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
	resultCh := make(chan error)
	sub := &invalidatedTxSubscription{
		mux:      mux,
		txHash:   txHash,
		resultCh: resultCh,
	}

	if _, exists := mux.invalidatedTxs.LoadOrStore(txHash, sub); exists {
		return nil, nil, fmt.Errorf("mux: transaction already exists")
	}

	return resultCh, sub, nil
}

func (mux *abciMux) registerGenesisHook(hook func()) {
	mux.Lock()
	defer mux.Unlock()

	mux.genesisHooks = append(mux.genesisHooks, hook)
}

func (mux *abciMux) registerHaltHook(hook func(context.Context, int64, epochtime.EpochTime)) {
	mux.Lock()
	defer mux.Unlock()

	mux.haltHooks = append(mux.haltHooks, hook)
}

func (mux *abciMux) Info(req types.RequestInfo) types.ResponseInfo {
	return types.ResponseInfo{
		AppVersion:       version.ConsensusProtocol.ToU64(),
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

	b, _ := json.Marshal(st)
	mux.logger.Debug("Genesis ABCI application state",
		"state", string(b),
	)

	mux.currentTime = st.Time

	// Stick the digest of the genesis block (the RequestInitChain) into
	// the state.
	//
	// This serves to keep bad things from happening if absolutely
	// nothing writes to the state till the Commit() call, along with
	// clearly separating chain instances based on the initialization
	// state, forever.
	tmp := bytes.NewBuffer(nil)
	_ = types.WriteMessage(&req, tmp)
	genesisDigest := sha512.Sum512_256(tmp.Bytes())
	mux.state.deliverTxTree.Set([]byte(stateKeyGenesisDigest), genesisDigest[:])

	resp := mux.BaseApplication.InitChain(req)

	// HACK: The state is only updated iff validators or consensus parameters
	// are returned.
	//
	// See: tendermint/consensus/replay.go (Handshaker.ReplayBlocks)
	if len(resp.Validators) == 0 && resp.ConsensusParams == nil {
		resp.ConsensusParams = req.ConsensusParams
	}

	// Dispatch registered genesis hooks.
	func() {
		mux.RLock()
		defer mux.RUnlock()

		mux.logger.Debug("Dispatching genesis hooks")

		for _, hook := range mux.genesisHooks {
			hook()
		}

		mux.logger.Debug("Genesis hook dispatch complete")
	}()

	// TODO: remove stateKeyGenesisRequest here, see oasis-core#2426
	b, _ = req.Marshal()
	mux.state.deliverTxTree.Set([]byte(stateKeyGenesisRequest), b)
	mux.state.checkTxTree.Set([]byte(stateKeyGenesisRequest), b)

	// Call InitChain() on all applications.
	mux.logger.Debug("InitChain: initializing applications")

	ctx := mux.state.NewContext(ContextInitChain, mux.currentTime)
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
	mux.state.deliverTxTree.Set([]byte(stateKeyInitChainEvents), evBinary)

	// Refresh consensus parameters.
	if err = mux.state.refreshConsensusParameters(); err != nil {
		panic(fmt.Errorf("mux: failed to refresh consensus parameters: %w", err))
	}

	return resp
}

func (mux *abciMux) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	blockHeight := mux.state.BlockHeight()

	mux.logger.Debug("BeginBlock",
		"req", req,
		"block_height", blockHeight,
	)

	// 99% sure this is a protocol violation.
	if mux.lastBeginBlock == blockHeight {
		panic("mux: redundant BeginBlock")
	}
	mux.lastBeginBlock = blockHeight
	mux.currentTime = req.Header.Time

	params, err := mux.state.ConsensusParameters()
	if err != nil {
		panic(fmt.Errorf("failed to fetch consensus parameters: %w", err))
	}

	// Create empty block context.
	mux.state.blockCtx = NewBlockContext()
	if params.MaxBlockGas > 0 {
		mux.state.blockCtx.Set(GasAccountantKey{}, NewGasAccountant(params.MaxBlockGas))
	} else {
		mux.state.blockCtx.Set(GasAccountantKey{}, NewNopGasAccountant())
	}
	// Create BeginBlock context.
	ctx := mux.state.NewContext(ContextBeginBlock, mux.currentTime)
	defer ctx.Close()

	currentEpoch, err := mux.state.GetCurrentEpoch(ctx.Ctx())
	if err != nil {
		panic("mux: can't get current epoch in BeginBlock")
	}

	// Check if there are any upgrades pending or if we need to halt for an upgrade.
	switch err = mux.upgrader.ConsensusUpgrade(ctx, currentEpoch, blockHeight); err {
	case nil:
		// Everything ok.
	case upgrade.ErrStopForUpgrade:
		panic("mux: reached upgrade epoch")
	default:
		panic(fmt.Sprintf("mux: error while trying to perform consensus upgrade: %v", err))
	}

	switch mux.state.haltMode {
	case false:
		if !mux.state.inHaltEpoch(ctx) {
			break
		}
		// On transition, trigger halt hooks.
		mux.logger.Info("BeginBlock: halt mode transition, emitting empty blocks.",
			"block_height", blockHeight,
			"epoch", mux.state.haltEpochHeight,
		)
		mux.logger.Debug("Dispatching halt hooks")
		for _, hook := range mux.haltHooks {
			hook(mux.state.ctx, blockHeight, mux.state.haltEpochHeight)
		}
		mux.logger.Debug("Halt hook dispatch complete")
		return types.ResponseBeginBlock{}
	case true:
		if !mux.state.afterHaltEpoch(ctx) {
			return types.ResponseBeginBlock{}
		}

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
			panic("mux: BeginBlock: fatal error in application: '" + app.Name() + "': " + err.Error())
		}
	}

	response := mux.BaseApplication.BeginBlock(req)

	// Collect and return events from the application's BeginBlock calls.
	response.Events = ctx.GetEvents()

	// During the first block, also collect and prepend application events
	// generated during InitChain to BeginBlock events.
	if mux.state.BlockHeight() == 0 {
		_, evBinary := mux.state.deliverTxTree.Get([]byte(stateKeyInitChainEvents))
		if evBinary != nil {
			var events []types.Event
			_ = cbor.Unmarshal(evBinary, &events)

			response.Events = append(events, response.Events...)

			mux.state.deliverTxTree.Remove([]byte(stateKeyInitChainEvents))
		}
	}

	return response
}

func (mux *abciMux) decodeTx(ctx *Context, rawTx []byte) (*transaction.Transaction, *transaction.SignedTransaction, error) {
	if mux.state.haltMode {
		ctx.Logger().Debug("executeTx: in halt, rejecting all transactions")
		return nil, nil, fmt.Errorf("halt mode, rejecting all transactions")
	}

	params, err := mux.state.ConsensusParameters()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
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

func (mux *abciMux) processTx(ctx *Context, tx *transaction.Transaction) error {
	// Pass the transaction through the fee handler if configured.
	if txAuthHandler := mux.state.txAuthHandler; txAuthHandler != nil {
		if err := txAuthHandler.AuthenticateTx(ctx, tx); err != nil {
			ctx.Logger().Debug("failed to authenticate transaction",
				"tx", tx,
				"tx_signer", ctx.TxSigner(),
				"method", tx.Method,
				"err", err,
			)
			return err
		}
	}

	// Route to correct handler.
	app := mux.appsByMethod[tx.Method]
	if app == nil {
		ctx.Logger().Error("unknown method",
			"tx", tx,
			"method", tx.Method,
		)
		return fmt.Errorf("mux: unknown method: %s", tx.Method)
	}

	ctx.Logger().Debug("dispatching",
		"app", app.Name(),
		"tx", tx,
	)

	if err := app.ExecuteTx(ctx, tx); err != nil {
		return err
	}

	// Run ForeignDeliverTx on all other applications so they can
	// run their post-tx hooks.
	for _, foreignApp := range mux.appsByLexOrder {
		if foreignApp == app {
			continue
		}

		if err := foreignApp.ForeignExecuteTx(ctx, app, tx); err != nil {
			return err
		}
	}

	return nil
}

func (mux *abciMux) executeTx(ctx *Context, rawTx []byte) error {
	tx, sigTx, err := mux.decodeTx(ctx, rawTx)
	if err != nil {
		return err
	}

	// Set authenticated transaction signer.
	ctx.SetTxSigner(sigTx.Signature.PublicKey)

	return mux.processTx(ctx, tx)
}

func (mux *abciMux) EstimateGas(caller signature.PublicKey, tx *transaction.Transaction) (transaction.Gas, error) {
	// As opposed to other transaction dispatch entry points (CheckTx/DeliverTx), this method can
	// be called in parallel to the consensus layer and to other invocations.
	//
	// For simulation mode, time will be filled in by NewContext from last block time.
	ctx := mux.state.NewContext(ContextSimulateTx, time.Time{})
	defer ctx.Close()

	ctx.SetTxSigner(caller)

	// Ignore any errors that occurred during simulation as we only need to estimate gas even if the
	// transaction seems like it will fail.
	_ = mux.processTx(ctx, tx)

	return ctx.Gas().GasUsed(), nil
}

func (mux *abciMux) notifyInvalidatedCheckTx(txHash hash.Hash, err error) {
	if item, exists := mux.invalidatedTxs.Load(txHash); exists {
		// Notify subscriber.
		sub := item.(*invalidatedTxSubscription)
		select {
		case sub.resultCh <- err:
		default:
		}
		close(sub.resultCh)

		mux.invalidatedTxs.Delete(txHash)
	}
}

func (mux *abciMux) CheckTx(req types.RequestCheckTx) types.ResponseCheckTx {
	if mux.state.disableCheckTx {
		// Blindly accept all transactions if configured to do so. We still need to periodically
		// remove old transactions as otherwise the mempool will fill up, so keep track of when
		// transactions were added and invalidate them after the configured interval.
		var txHash hash.Hash
		txHash.FromBytes(req.Tx)

		if req.Type == types.CheckTxType_Recheck {
			// Check timestamp.
			if ts, ok := mux.debugExpiringTxs[txHash]; ok && mux.currentTime.Sub(ts) > debugTxLifetime {
				delete(mux.debugExpiringTxs, txHash)

				err := fmt.Errorf("mux: transaction expired (debug only)")
				mux.notifyInvalidatedCheckTx(txHash, err)

				return types.ResponseCheckTx{
					Codespace: errors.UnknownModule,
					Code:      1,
					Log:       err.Error(),
				}
			}
		} else {
			mux.debugExpiringTxs[txHash] = mux.currentTime
		}

		return types.ResponseCheckTx{
			Code: types.CodeTypeOK,
		}
	}

	ctx := mux.state.NewContext(ContextCheckTx, mux.currentTime)
	defer ctx.Close()

	if err := mux.executeTx(ctx, req.Tx); err != nil {
		module, code := errors.Code(err)

		if req.Type == types.CheckTxType_Recheck {
			// This is a re-check and the transaction just failed validation. Since
			// the mempool provides no way of getting notified when a previously
			// valid transaction becomes invalid, handle this here.

			// XXX: The Tendermint mempool should have provisions for this instead
			//      of us hacking our way through this here.
			var txHash hash.Hash
			txHash.FromBytes(req.Tx)

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
	ctx := mux.state.NewContext(ContextDeliverTx, mux.currentTime)
	defer ctx.Close()

	if err := mux.executeTx(ctx, req.Tx); err != nil {
		module, code := errors.Code(err)

		return types.ResponseDeliverTx{
			Codespace: module,
			Code:      code,
			Log:       err.Error(),
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

	ctx := mux.state.NewContext(ContextEndBlock, mux.currentTime)
	defer ctx.Close()

	// Fire all application timers first.
	for _, app := range mux.appsByLexOrder {
		if err := fireTimers(ctx, app); err != nil {
			mux.logger.Error("EndBlock: fatal error during timer fire",
				"err", err,
				"app", app.Name(),
			)
			panic("mux: EndBlock: fatal error in application: '" + app.Name() + "': " + err.Error())
		}
	}

	// Dispatch EndBlock to all applications.
	resp := mux.BaseApplication.EndBlock(req)
	for _, app := range mux.appsByLexOrder {
		newResp, err := app.EndBlock(ctx, req)
		if err != nil {
			mux.logger.Error("EndBlock: fatal error in application",
				"err", err,
				"app", app.Name(),
			)
			panic("mux: EndBlock: fatal error in application: '" + app.Name() + "': " + err.Error())
		}
		if app.Blessed() {
			resp = newResp
		}
	}

	// Update tags.
	resp.Events = ctx.GetEvents()

	// Clear block context.
	mux.state.blockCtx = nil

	return resp
}

func (mux *abciMux) Commit() types.ResponseCommit {
	if err := mux.state.doCommit(mux.currentTime); err != nil {
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
	)

	return types.ResponseCommit{Data: mux.state.BlockHash()}
}

func (mux *abciMux) doCleanup() {
	mux.state.doCleanup()

	for _, v := range mux.appsByLexOrder {
		v.OnCleanup()
	}
}

func (mux *abciMux) doRegister(app Application) error {
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

	app.OnRegister(mux.state)
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

	mux.appsByLexOrder = make([]Application, 0, numApps)
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

func newABCIMux(ctx context.Context, upgrader upgrade.Backend, cfg *ApplicationConfig) (*abciMux, error) {
	state, err := newApplicationState(ctx, cfg)
	if err != nil {
		return nil, err
	}

	mux := &abciMux{
		logger:         logging.GetLogger("abci-mux"),
		upgrader:       upgrader,
		state:          state,
		appsByName:     make(map[string]Application),
		appsByMethod:   make(map[transaction.MethodName]Application),
		lastBeginBlock: -1,
	}

	// Create a map of expiring transactions if CheckTx is disabled (debug only).
	if state.disableCheckTx {
		mux.debugExpiringTxs = make(map[hash.Hash]time.Time)
	}

	mux.logger.Debug("ABCI multiplexer initialized",
		"block_height", state.BlockHeight(),
		"block_hash", hex.EncodeToString(state.BlockHash()),
	)

	return mux, nil
}
