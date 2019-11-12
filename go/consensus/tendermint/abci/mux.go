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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	dbm "github.com/tendermint/tm-db"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/common/version"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/db"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
)

const (
	// QueryKeyP2PFilterAddr is the standard ABCI query by IP address
	// used to determine if a peer is authorized to connect.
	QueryKeyP2PFilterAddr = "p2p/filter/addr/"

	// QueryKeyP2PFilterPubkey is the standard ABCI query by public key
	// used to determine if a peer is authorized to connect.
	QueryKeyP2PFilterPubkey = "p2p/filter/pubkey/"

	stateKeyGenesisDigest  = "OasisGenesisDigest"
	stateKeyGenesisRequest = "OasisGenesisRequest"

	metricsUpdateInterval = 10 * time.Second
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

	errOversizedTx = fmt.Errorf("mux: oversized transaction")
)

// ApplicationConfig is the configuration for the consensus application.
type ApplicationConfig struct {
	DataDir         string
	Pruning         PruneConfig
	HaltEpochHeight epochtime.EpochTime
	MinGasPrice     uint64
}

// Application is the interface implemented by multiplexed Oasis-specific
// ABCI applications.
type Application interface {
	// Name returns the name of the Application.
	//
	// Note: The name is also used as a prefix for de-multiplexing SetOption
	// and Query calls and accessing genesis state.
	Name() string

	// TransactionTag returns the transaction tag used to disambiguate
	// CheckTx and DeliverTx calls.
	TransactionTag() byte

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
	OnRegister(state *ApplicationState)

	// OnCleanup is the function that is called when the ApplicationServer
	// has been halted.
	OnCleanup()

	// SetOption sets set an application option.
	//
	// It is expected that the key is prefixed by the application name
	// followed by a '/' (eg: `foo/<some key here>`).
	SetOption(types.RequestSetOption) types.ResponseSetOption

	// ExecuteTx executes a transaction.
	ExecuteTx(*Context, []byte) error

	// ForeignExecuteTx delivers a transaction of another application for
	// processing.
	//
	// This can be used to run post-tx hooks when dependencies exist
	// between applications.
	ForeignExecuteTx(*Context, Application, []byte) error

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
// XXX: epochtime needs to be set before mux can be used.
func (a *ApplicationServer) SetEpochtime(epochTime epochtime.Backend) {
	a.mux.state.timeSource = epochTime
}

// NewApplicationServer returns a new ApplicationServer, using the provided
// directory to persist state.
func NewApplicationServer(ctx context.Context, cfg *ApplicationConfig) (*ApplicationServer, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(abciCollectors...)
	})

	mux, err := newABCIMux(ctx, cfg)
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
	state  *ApplicationState

	appsByName     map[string]Application
	appsByTxTag    map[byte]Application
	appsByLexOrder []Application
	appBlessed     Application

	lastBeginBlock int64
	currentTime    time.Time
	maxTxSize      uint64

	genesisHooks []func()
	haltHooks    []func(context.Context, int64, epochtime.EpochTime)
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
		AppVersion:       version.BackendProtocol.ToU64(),
		LastBlockHeight:  mux.state.BlockHeight(),
		LastBlockAppHash: mux.state.BlockHash(),
	}
}

func (mux *abciMux) SetOption(req types.RequestSetOption) types.ResponseSetOption {
	app, err := mux.extractAppFromKeyPath(req.GetKey())
	if err != nil {
		mux.logger.Error("SetOption: failed to de-multiplex",
			"req", req,
			"err", err,
		)
		return types.ResponseSetOption{
			Code: api.CodeInvalidApplication.ToInt(),
		}
	}

	mux.logger.Debug("SetOption: dispatching",
		"app", app.Name(),
		"req", req,
	)

	return app.SetOption(req)
}

func (mux *abciMux) Query(req types.RequestQuery) types.ResponseQuery {
	queryPath := req.GetPath()

	// Tendermint uses these queries to filter incoming connections
	// by source address and or link(?) public key.  Offload the
	// responsiblity onto the blessed app.
	if isP2PFilterQuery(queryPath) {
		// TODO: Handle P2P filter queries.

		mux.logger.Debug("Query: allowing p2p/filter query",
			"req", req,
		)
		return types.ResponseQuery{
			Code: api.CodeOK.ToInt(),
		}
	}

	return types.ResponseQuery{
		Code: api.CodeInvalidQuery.ToInt(),
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

	if mux.maxTxSize = st.Consensus.Parameters.MaxTxSize; mux.maxTxSize == 0 {
		mux.logger.Warn("maximum transaction size enforcement is disabled")
	}

	b, _ := json.Marshal(st)
	mux.logger.Debug("Genesis ABCI application state",
		"state", string(b),
	)

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

	// HACK: Can't emit tags from InitChain, stash the genesis state
	// so that processing can happen in BeginBlock.
	//
	// This is also stashed in the CheckTx tree (even though it will get
	// rolled back), so that it is usable from the genesisHooks.
	b, _ = req.Marshal()
	mux.state.deliverTxTree.Set([]byte(stateKeyGenesisRequest), b)
	mux.state.checkTxTree.Set([]byte(stateKeyGenesisRequest), b)

	resp := mux.BaseApplication.InitChain(req)

	// HACK: The state is only updated iff validators or consensus paremeters
	// are returned.
	//
	// See: tendermint/consensus/replay.go (Handshaker.ReplayBlocks)
	if len(resp.Validators) == 0 && resp.ConsensusParams == nil {
		resp.ConsensusParams = req.ConsensusParams
	}

	// Dispatch registered genesis hooks.
	mux.RLock()
	defer mux.RUnlock()

	mux.logger.Debug("Dispatching genesis hooks")

	for _, hook := range mux.genesisHooks {
		hook()
	}

	mux.logger.Debug("Genesis hook dispatch complete")

	return resp
}

func (s *ApplicationState) inHaltEpoch(ctx *Context) bool {
	blockHeight := s.BlockHeight()

	currentEpoch, err := s.GetEpoch(ctx.Ctx(), blockHeight+1)
	if err != nil {
		s.logger.Error("inHaltEpoch: failed to get epoch",
			"err", err,
			"block_height", blockHeight+1,
		)
		return false
	}
	s.haltMode = currentEpoch == s.haltEpochHeight
	return s.haltMode
}

func (s *ApplicationState) afterHaltEpoch(ctx *Context) bool {
	blockHeight := s.BlockHeight()

	currentEpoch, err := s.GetEpoch(ctx.Ctx(), blockHeight+1)
	if err != nil {
		s.logger.Error("afterHaltEpoch: failed to get epoch",
			"err", err,
			"block_height", blockHeight,
		)
		return false
	}

	return currentEpoch > s.haltEpochHeight
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

	// Create empty block context.
	mux.state.blockCtx = NewBlockContext()
	// Create BeginBlock context.
	ctx := NewContext(ContextBeginBlock, mux.currentTime, mux.state)

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

	// HACK: Our entire system is driven with a tag backed pub-sub
	// interface gluing the various components together.  While we
	// desire to have things that would emit tags (like runtime
	// registration) in InitChain, and tendermint does not allow
	// emiting tags in the ABCI InitChain hook, we defer actually
	// initializing the multiplexed application genesis state till
	// the first block.
	if blockHeight == 1 {
		mux.logger.Debug("BeginBlock: processing defered InitChain")

		_, b := mux.state.checkTxTree.Get([]byte(stateKeyGenesisRequest))

		var initReq types.RequestInitChain
		if err := initReq.Unmarshal(b); err != nil {
			mux.logger.Error("BeginBlock: corrupted defered genesis state",
				"err", err,
			)
			panic("mux: invalid defered genesis application state")
		}

		doc, err := parseGenesisAppState(initReq)
		if err != nil {
			mux.logger.Error("BeginBlock: corrupted defered genesis state",
				"err", err,
			)
			panic("mux: invalid defered genesis application state")
		}

		ctx.outputType = ContextInitChain

		for _, app := range mux.appsByLexOrder {
			mux.logger.Debug("BeginBlock: defered InitChain",
				"app", app.Name(),
			)

			if err = app.InitChain(ctx, initReq, doc); err != nil {
				mux.logger.Error("BeginBlock: defered InitChain, fatal error in application",
					"err", err,
					"app", app.Name(),
				)
				panic("mux: BeginBlock: defered InitChain, fatal error in application: '" + app.Name() + "': " + err.Error())
			}
		}

		ctx.outputType = ContextBeginBlock
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
	response.Events = ctx.GetEvents()

	return response
}

func (mux *abciMux) executeTx(ctx *Context, tx []byte) error {
	logger := mux.logger.With("is_check_only", ctx.IsCheckOnly())

	if mux.state.haltMode {
		logger.Debug("executeTx: in halt, rejecting all transactions")
		return fmt.Errorf("halt mode, rejecting all transactions")
	}

	if mux.maxTxSize > 0 && uint64(len(tx)) > mux.maxTxSize {
		// This deliberately avoids logging the tx since spamming the
		// logs is also bad.
		logger.Error("received oversized transaction",
			"tx_size", len(tx),
		)
		return errOversizedTx
	}

	app, err := mux.extractAppFromTx(tx)
	if err != nil {
		logger.Error("failed to de-multiplex",
			"tx", base64.StdEncoding.EncodeToString(tx),
		)
		return err
	}

	logger.Debug("dispatching",
		"app", app.Name(),
		"tx", base64.StdEncoding.EncodeToString(tx),
	)

	if err = app.ExecuteTx(ctx, tx[1:]); err != nil {
		return err
	}

	// Run ForeignDeliverTx on all other applications so they can
	// run their post-tx hooks.
	for _, foreignApp := range mux.appsByLexOrder {
		if foreignApp == app {
			continue
		}

		if err = foreignApp.ForeignExecuteTx(ctx, app, tx[1:]); err != nil {
			return err
		}
	}

	return nil
}

func (mux *abciMux) CheckTx(req types.RequestCheckTx) types.ResponseCheckTx {
	ctx := NewContext(ContextCheckTx, mux.currentTime, mux.state)

	if err := mux.executeTx(ctx, req.Tx); err != nil {
		return types.ResponseCheckTx{
			Code: api.CodeTransactionFailed.ToInt(),
			Info: err.Error(),
		}
	}

	return types.ResponseCheckTx{
		Code: api.CodeOK.ToInt(),
	}
}

func (mux *abciMux) DeliverTx(req types.RequestDeliverTx) types.ResponseDeliverTx {
	ctx := NewContext(ContextDeliverTx, mux.currentTime, mux.state)

	if err := mux.executeTx(ctx, req.Tx); err != nil {
		return types.ResponseDeliverTx{
			Code: api.CodeTransactionFailed.ToInt(),
			Info: err.Error(),
		}
	}

	return types.ResponseDeliverTx{
		Code:   api.CodeOK.ToInt(),
		Data:   cbor.Marshal(ctx.Data()),
		Events: ctx.GetEvents(),
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

	ctx := NewContext(ContextEndBlock, mux.currentTime, mux.state)

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
	if err := mux.state.doCommit(); err != nil {
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
	mux.appsByTxTag[app.TransactionTag()] = app
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

func (mux *abciMux) extractAppFromKeyPath(s string) (Application, error) {
	appName := s
	if strings.Contains(appName, "/") {
		sVec := strings.SplitN(appName, "/", 2)
		appName = sVec[0]
	}

	app, ok := mux.appsByName[appName]
	if !ok {
		return nil, fmt.Errorf("mux: unknown app: '%s'", appName)
	}

	return app, nil
}

func (mux *abciMux) extractAppFromTx(tx []byte) (Application, error) {
	if len(tx) == 0 {
		return nil, fmt.Errorf("mux: invalid transaction")
	}

	app, ok := mux.appsByTxTag[tx[0]]
	if !ok {
		return nil, fmt.Errorf("mux: unknown transaction tag: 0x%x", tx[0])
	}

	return app, nil
}

func newABCIMux(ctx context.Context, cfg *ApplicationConfig) (*abciMux, error) {
	state, err := newApplicationState(ctx, cfg)
	if err != nil {
		return nil, err
	}

	mux := &abciMux{
		logger:         logging.GetLogger("abci-mux"),
		state:          state,
		appsByName:     make(map[string]Application),
		appsByTxTag:    make(map[byte]Application),
		lastBeginBlock: -1,
	}

	mux.logger.Debug("ABCI multiplexer initialized",
		"block_height", state.BlockHeight(),
		"block_hash", hex.EncodeToString(state.BlockHash()),
	)

	return mux, nil
}

// ApplicationState is the overall past, present and future state
// of all multiplexed applications.
type ApplicationState struct {
	logger *logging.Logger

	ctx           context.Context
	db            dbm.DB
	deliverTxTree *iavl.MutableTree
	checkTxTree   *iavl.MutableTree
	statePruner   StatePruner

	blockLock   sync.RWMutex
	blockHash   []byte
	blockHeight int64
	blockCtx    *BlockContext

	timeSource epochtime.Backend

	haltMode        bool
	haltEpochHeight epochtime.EpochTime

	minGasPrice quantity.Quantity

	metricsCloseCh  chan struct{}
	metricsClosedCh chan struct{}
}

// BlockHeight returns the last committed block height.
func (s *ApplicationState) BlockHeight() int64 {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	return s.blockHeight
}

// BlockHash returns the last committed block hash.
func (s *ApplicationState) BlockHash() []byte {
	s.blockLock.RLock()
	defer s.blockLock.RUnlock()

	return append([]byte{}, s.blockHash...)
}

// BlockContext returns the current block context which can be used
// to store intermediate per-block results.
//
// This method must only be called from BeginBlock/DeliverTx/EndBlock
// and calls from anywhere else will cause races.
func (s *ApplicationState) BlockContext() *BlockContext {
	return s.blockCtx
}

// DeliverTxTree returns the versioned tree to be used by queries
// to view comitted data, and transactions to build the next version.
func (s *ApplicationState) DeliverTxTree() *iavl.MutableTree {
	return s.deliverTxTree
}

// CheckTxTree returns the state tree to be used for modifications
// inside CheckTx (mempool connection) calls.
//
// This state is never persisted.
func (s *ApplicationState) CheckTxTree() *iavl.MutableTree {
	return s.checkTxTree
}

// GetBaseEpoch returns the base epoch.
func (s *ApplicationState) GetBaseEpoch() (epochtime.EpochTime, error) {
	return s.timeSource.GetBaseEpoch(s.ctx)
}

// GetEpoch returns current epoch at block height.
func (s *ApplicationState) GetEpoch(ctx context.Context, blockHeight int64) (epochtime.EpochTime, error) {
	return s.timeSource.GetEpoch(ctx, blockHeight)
}

// EpochChanged returns true iff the current epoch has changed since the
// last block.  As a matter of convenience, the current epoch is returned.
func (s *ApplicationState) EpochChanged(ctx *Context) (bool, epochtime.EpochTime) {
	blockHeight := s.BlockHeight()
	if blockHeight == 0 {
		return false, epochtime.EpochInvalid
	} else if blockHeight == 1 {
		// There is no block before the first block. For historic reasons, this is defined as not
		// having had a transition.
		currentEpoch, err := s.timeSource.GetEpoch(ctx.Ctx(), blockHeight)
		if err != nil {
			s.logger.Error("EpochChanged: failed to get current epoch",
				"err", err,
			)
			return false, epochtime.EpochInvalid
		}
		return false, currentEpoch
	}

	previousEpoch, err := s.timeSource.GetEpoch(ctx.Ctx(), blockHeight)
	if err != nil {
		s.logger.Error("EpochChanged: failed to get previous epoch",
			"err", err,
		)
		return false, epochtime.EpochInvalid
	}
	currentEpoch, err := s.timeSource.GetEpoch(ctx.Ctx(), blockHeight+1)
	if err != nil {
		s.logger.Error("EpochChanged: failed to get current epoch",
			"err", err,
		)
		return false, epochtime.EpochInvalid
	}

	if previousEpoch == currentEpoch {
		return false, currentEpoch
	}

	s.logger.Debug("EpochChanged: epoch transition detected",
		"prev_epoch", previousEpoch,
		"epoch", currentEpoch,
	)

	return true, currentEpoch
}

// Genesis returns the ABCI genesis state.
func (s *ApplicationState) Genesis() *genesis.Document {
	_, b := s.checkTxTree.Get([]byte(stateKeyGenesisRequest))

	var req types.RequestInitChain
	if err := req.Unmarshal(b); err != nil {
		s.logger.Error("Genesis: corrupted defered genesis state",
			"err", err,
		)
		panic("Genesis: invalid defered genesis application state")
	}

	st, err := parseGenesisAppState(req)
	if err != nil {
		s.logger.Error("failed to unmarshal genesis application state",
			"err", err,
			"state", req.AppStateBytes,
		)
		panic("Genesis: invalid genesis application state")
	}

	return st
}

// MinGasPrice returns the configured minimum gas price.
func (s *ApplicationState) MinGasPrice() *quantity.Quantity {
	return &s.minGasPrice
}

func (s *ApplicationState) doCommit() error {
	// Save the new version of the persistent tree.
	blockHash, blockHeight, err := s.deliverTxTree.SaveVersion()
	if err == nil {
		s.blockLock.Lock()
		s.blockHash = blockHash
		s.blockHeight = blockHeight
		s.blockLock.Unlock()

		// Reset CheckTx state to latest version. This is safe because
		// Tendermint holds a lock on the mempool for commit.
		//
		// WARNING: deliverTxTree and checkTxTree do not share internal
		// state beyond the backing database.  The `LoadVersion`
		// implementation MUST be written in a way to avoid relying on
		// cached metadata.
		//
		// This makes the upstream `LazyLoadVersion` and `LoadVersion`
		// unsuitable for our use case.
		_, cerr := s.checkTxTree.LoadVersion(blockHeight)
		if cerr != nil {
			panic(cerr)
		}

		// Prune the iavl state according to the specified strategy.
		s.statePruner.Prune(s.blockHeight)
	}

	return err
}

func (s *ApplicationState) doCleanup() {
	if s.db != nil {
		// Don't close the DB out from under the metrics worker.
		close(s.metricsCloseCh)
		<-s.metricsClosedCh

		s.db.Close()
		s.db = nil
	}
}

func (s *ApplicationState) updateMetrics() error {
	var dbSize int64

	switch m := s.db.(type) {
	case *dbm.GoLevelDB:
		var stats leveldb.DBStats
		if err := m.DB().Stats(&stats); err != nil {
			s.logger.Error("Stats",
				"err", err,
			)
			return err
		}

		for _, v := range stats.LevelSizes {
			dbSize += v
		}
	case api.SizeableDB:
		var err error
		if dbSize, err = m.Size(); err != nil {
			s.logger.Error("Size",
				"err", err,
			)
			return err
		}
	default:
		return fmt.Errorf("state: unsupported DB for metrics")
	}

	abciSize.Set(float64(dbSize) / 1024768.0)

	return nil
}

func (s *ApplicationState) metricsWorker() {
	defer close(s.metricsClosedCh)

	// Update the metrics once on initialization.
	if err := s.updateMetrics(); err != nil {
		// If this fails, don't bother trying again, it's most likely
		// an unsupported DB backend.
		s.logger.Warn("metrics not available",
			"err", err,
		)
		return
	}

	t := time.NewTicker(metricsUpdateInterval)
	defer t.Stop()

	for {
		select {
		case <-s.metricsCloseCh:
			return
		case <-t.C:
			_ = s.updateMetrics()
		}
	}
}

func newApplicationState(ctx context.Context, cfg *ApplicationConfig) (*ApplicationState, error) {
	db, err := db.New(filepath.Join(cfg.DataDir, "abci-mux-state"), false)
	if err != nil {
		return nil, err
	}

	// Figure out the latest version/hash if any, and use that
	// as the block height/hash.
	deliverTxTree := iavl.NewMutableTree(db, 128)
	blockHeight, err := deliverTxTree.Load()
	if err != nil {
		db.Close()
		return nil, err
	}
	blockHash := deliverTxTree.Hash()

	checkTxTree := iavl.NewMutableTree(db, 128)
	checkTxBlockHeight, err := checkTxTree.Load()
	if err != nil {
		db.Close()
		return nil, err
	}

	if blockHeight != checkTxBlockHeight || !bytes.Equal(blockHash, checkTxTree.Hash()) {
		db.Close()
		return nil, fmt.Errorf("state: inconsistent trees")
	}

	statePruner, err := newStatePruner(&cfg.Pruning, deliverTxTree, blockHeight)
	if err != nil {
		db.Close()
		return nil, err
	}

	var minGasPrice quantity.Quantity
	if err = minGasPrice.FromInt64(int64(cfg.MinGasPrice)); err != nil {
		return nil, fmt.Errorf("state: invalid minimum gas price: %w", err)
	}

	s := &ApplicationState{
		logger:          logging.GetLogger("abci-mux/state"),
		ctx:             ctx,
		db:              db,
		deliverTxTree:   deliverTxTree,
		checkTxTree:     checkTxTree,
		statePruner:     statePruner,
		blockHash:       blockHash,
		blockHeight:     blockHeight,
		haltEpochHeight: cfg.HaltEpochHeight,
		minGasPrice:     minGasPrice,
		metricsCloseCh:  make(chan struct{}),
		metricsClosedCh: make(chan struct{}),
	}
	go s.metricsWorker()

	return s, nil
}

func isP2PFilterQuery(s string) bool {
	return strings.HasPrefix(s, QueryKeyP2PFilterAddr) || strings.HasPrefix(s, QueryKeyP2PFilterPubkey)
}

func parseGenesisAppState(req types.RequestInitChain) (*genesis.Document, error) {
	var st genesis.Document
	if err := json.Unmarshal(req.AppStateBytes, &st); err != nil {
		return nil, err
	}

	return &st, nil
}
