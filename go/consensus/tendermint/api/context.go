package api

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

type contextKey struct{}

// ContextMode is a context mode.
type ContextMode uint

const (
	// ContextInvalid is invalid context and should never be used.
	ContextInvalid ContextMode = iota
	// ContextInitChain is InitChain context.
	ContextInitChain
	// ContextCheckTx is CheckTx context.
	ContextCheckTx
	// ContextDeliverTx is DeliverTx context.
	ContextDeliverTx
	// ContextSimulateTx is SimulateTx context.
	ContextSimulateTx
	// ContextBeginBlock is BeginBlock context.
	ContextBeginBlock
	// ContextEndBlock is EndBlock context.
	ContextEndBlock
)

// String returns a string representation of the context mode.
func (m ContextMode) String() string {
	switch m {
	case ContextInitChain:
		return "init chain"
	case ContextCheckTx:
		return "check tx"
	case ContextDeliverTx:
		return "deliver tx"
	case ContextSimulateTx:
		return "simulate tx"
	case ContextBeginBlock:
		return "begin block"
	case ContextEndBlock:
		return "end block"
	default:
		return "[invalid]"
	}
}

// Context is the context of processing a transaction/block.
type Context struct { // nolint: maligned
	context.Context

	parent *Context

	mode        ContextMode
	currentTime time.Time

	isMessageExecution bool
	isTransaction      bool

	data          interface{}
	events        []types.Event
	gasAccountant GasAccountant

	txSigner      signature.PublicKey
	callerAddress staking.Address

	appState      ApplicationState
	state         mkvs.KeyValueTree
	blockHeight   int64
	blockCtx      *BlockContext
	initialHeight int64

	logger *logging.Logger
}

// FromCtx extracts an ABCI context from a context.Context if one has been
// set. Otherwise it returns nil.
func FromCtx(ctx context.Context) *Context {
	abciCtx, _ := ctx.Value(contextKey{}).(*Context)
	return abciCtx
}

// NewContext creates a new context.
func NewContext(
	ctx context.Context,
	mode ContextMode,
	currentTime time.Time,
	gasAccountant GasAccountant,
	appState ApplicationState,
	state mkvs.Tree,
	blockHeight int64,
	blockCtx *BlockContext,
	initialHeight int64,
) *Context {
	c := &Context{
		mode:          mode,
		currentTime:   currentTime,
		gasAccountant: gasAccountant,
		appState:      appState,
		state:         state,
		blockHeight:   blockHeight,
		blockCtx:      blockCtx,
		initialHeight: initialHeight,
		logger:        logging.GetLogger("consensus/tendermint/abci").With("mode", mode),
	}
	c.Context = context.WithValue(ctx, contextKey{}, c)
	return c
}

// Close releases all resources associated with this context.
//
// After calling this method, the context should no longer be used.
func (c *Context) Close() {
	switch c.parent {
	case nil:
		// This is the top-level context.
		if c.IsSimulation() {
			if tree, ok := c.state.(mkvs.ClosableTree); ok {
				tree.Close()
			}
		}
	default:
		// This is a child context.
		switch c.isTransaction {
		case true:
			// Transaction mode requires explicit commit, just make sure to cleanup the checkpoint.
			c.state.(mkvs.OverlayTree).Close()
		case false:
			// Non-transaction mode, propagate events.
			if !c.IsSimulation() {
				c.parent.events = append(c.parent.events, c.events...)
			}
		}
	}

	c.parent = nil
	c.events = nil
	c.appState = nil
	c.state = nil
	c.blockCtx = nil
	c.Context = nil
}

// Logger returns the logger associated with this context.
func (c *Context) Logger() *logging.Logger {
	return c.logger
}

// Mode returns the context mode.
func (c *Context) Mode() ContextMode {
	return c.mode
}

// Data returns the data to be serialized with this output.
func (c *Context) Data() interface{} {
	return c.data
}

// TxSigner returns the authenticated transaction signer.
//
// In case the method is called on a non-transaction context, this method
// will panic.
func (c *Context) TxSigner() signature.PublicKey {
	switch c.mode {
	case ContextCheckTx, ContextDeliverTx, ContextSimulateTx:
		return c.txSigner
	default:
		panic("context: only available in transaction context")
	}
}

// SetTxSigner sets the authenticated transaction signer.
//
// This must only be done after verifying the transaction signature.
//
// In case the method is called on a non-transaction context, this method
// will panic.
func (c *Context) SetTxSigner(txSigner signature.PublicKey) {
	switch c.mode {
	case ContextCheckTx, ContextDeliverTx, ContextSimulateTx:
		c.txSigner = txSigner
		// By default, the caller is the transaction signer.
		c.callerAddress = staking.NewAddress(txSigner)
	default:
		panic("context: only available in transaction context")
	}
}

// CallerAddress returns the authenticated address representing the caller.
func (c *Context) CallerAddress() staking.Address {
	return c.callerAddress
}

// NewChild creates a new child context that shares state with the current context.
//
// If you want isolated state and events use NewTransaction instad.
func (c *Context) NewChild() *Context {
	cc := &Context{
		parent:             c,
		mode:               c.mode,
		currentTime:        c.currentTime,
		isMessageExecution: c.isMessageExecution,
		gasAccountant:      c.gasAccountant,
		txSigner:           c.txSigner,
		callerAddress:      c.callerAddress,
		appState:           c.appState,
		state:              c.state,
		blockHeight:        c.blockHeight,
		blockCtx:           c.blockCtx,
		initialHeight:      c.initialHeight,
		logger:             c.logger,
	}
	cc.Context = context.WithValue(c.Context, contextKey{}, cc)
	return cc
}

// NewTransaction creates a new transaction child context.
//
// This automatically starts a new state checkpoint and the context must be explicitly committed by
// calling Commit otherwise both state and events will be reverted.
//
// NOTE: This does NOT isolate anything other than state and events.
func (c *Context) NewTransaction() *Context {
	cc := c.NewChild()
	cc.isTransaction = true
	// Create isolated state.
	cc.state = mkvs.NewOverlay(c.state)
	return cc
}

// Commit commits state updates and emitted events in this transaction child context previously
// created via NewTransaction. Returns the parent context.
//
// If this is not a transaction child context, the method has no effect.
func (c *Context) Commit() *Context {
	if !c.isTransaction {
		return c.parent
	}

	// Commit state.
	// NOTE: Since isTransaction is true, we know that c.state is a mkvs.OverlayTree.
	if err := c.state.(mkvs.OverlayTree).Commit(c); err != nil {
		panic(fmt.Errorf("failed to commit overlay: %w", err))
	}

	// Commit events.
	// NOTE: Since isTransaction is true, we know c.parent is non-nil.
	c.parent.events = append(c.parent.events, c.events...)
	c.events = nil

	return c.parent
}

// WithCallerAddress creates a child context and sets a specific tx address.
func (c *Context) WithCallerAddress(callerAddress staking.Address) *Context {
	child := c.NewChild()
	child.callerAddress = callerAddress
	return child
}

// WithSimulation creates a child context in simulation mode.
//
// Note that state is unchanged -- if you want to prevent propagation of state updates, start a
// checkpoint manually.
func (c *Context) WithSimulation() *Context {
	child := c.NewChild()
	child.mode = ContextSimulateTx
	child.logger = child.logger.With("mode", child.mode)
	return child
}

// WithMessageExecution creates a child context and sets the message execution flag.
func (c *Context) WithMessageExecution() *Context {
	child := c.NewChild()
	child.isMessageExecution = true
	return child
}

// IsInitChain returns true if this ia an init chain context.
func (c *Context) IsInitChain() bool {
	return c.mode == ContextInitChain
}

// IsCheckOnly returns true if this is a CheckTx context.
func (c *Context) IsCheckOnly() bool {
	return c.mode == ContextCheckTx
}

// IsSimulation returns true if this is a simulation-only context.
func (c *Context) IsSimulation() bool {
	return c.mode == ContextSimulateTx
}

// IsMessageExecution returns true if this is a message execution context.
func (c *Context) IsMessageExecution() bool {
	return c.isMessageExecution
}

// EmitData emits data to be serialized as transaction output.
//
// Note: The use of this has mostly been replaced with EmitEvent, please
// think really carefully if you want to use this.
func (c *Context) EmitData(data interface{}) {
	c.data = data
}

// EmitEvent emits an ABCI event for the current transaction/block.
// Note: If the event has no attributes, this routine will do nothing.
func (c *Context) EmitEvent(bld *EventBuilder) {
	if bld.Dirty() {
		c.events = append(c.events, bld.Event())
	}
}

// GetEvents returns the ABCI event vector corresponding to the tags.
func (c *Context) GetEvents() []types.Event {
	return c.events
}

// HasEvent checks if a specific event has been emitted.
func (c *Context) HasEvent(app string, key []byte) bool {
	evType := EventTypeForApp(app)

	for _, ev := range c.events {
		if ev.Type != evType {
			continue
		}

		for _, pair := range ev.Attributes {
			if bytes.Equal(pair.GetKey(), key) {
				return true
			}
		}
	}
	return false
}

// HasTypedEvent checks if a specific typed event has been emitted.
func (c *Context) HasTypedEvent(app string, kind TypedAttribute) bool {
	return c.HasEvent(app, []byte(kind.EventKind()))
}

// DecodeTypedEvent decodes the given raw event as a specific typed event.
func (c *Context) DecodeTypedEvent(index int, ev TypedAttribute) error {
	raw := c.events[index]
	for _, pair := range raw.Attributes {
		if bytes.Equal(pair.GetKey(), []byte(ev.EventKind())) {
			return cbor.Unmarshal(pair.GetValue(), ev)
		}
	}
	return fmt.Errorf("incompatible event")
}

// SetGasAccountant configures the gas accountant on the context.
func (c *Context) SetGasAccountant(ga GasAccountant) {
	c.gasAccountant = ga
}

// Gas returns the gas accountant.
func (c *Context) Gas() GasAccountant {
	return c.gasAccountant
}

// Now returns the current tendermint time.
func (c *Context) Now() time.Time {
	return c.currentTime
}

// State returns the state tree associated with this context.
func (c *Context) State() mkvs.KeyValueTree {
	return c.state
}

// AppState returns the application state.
//
// Accessing application state in simulation mode is not allowed and will result in a panic.
func (c *Context) AppState() ApplicationState {
	if c.IsSimulation() {
		panic("context: application state is not available in simulation mode")
	}
	return c.appState
}

// InitialHeight returns the initial height.
func (c *Context) InitialHeight() int64 {
	return c.initialHeight
}

// BlockHeight returns the current block height.
func (c *Context) BlockHeight() int64 {
	return c.blockHeight
}

// BlockContext returns the current block context.
//
// In case there is no current block (e.g., because the current context is not
// an execution context), this will return nil.
func (c *Context) BlockContext() *BlockContext {
	return c.blockCtx
}

// BlockContextKey is an interface for a block context key.
type BlockContextKey interface {
	// NewDefault returns a new default value for the given key.
	NewDefault() interface{}
}

// BlockContext can be used to store arbitrary key/value pairs for state that
// is needed while processing a block.
//
// When a block is committed, this context is automatically reset.
type BlockContext struct {
	storage map[BlockContextKey]interface{}
}

// Get returns the value stored under the given key (if any). If no value
// currently exists, the NewDefault method is called on the key to produce a
// default value and that value is stored.
func (bc *BlockContext) Get(key BlockContextKey) interface{} {
	v, ok := bc.storage[key]
	if !ok {
		v = key.NewDefault()
		bc.storage[key] = v
	}
	return v
}

// Set overwrites the value stored under the given key.
func (bc *BlockContext) Set(key BlockContextKey, value interface{}) {
	bc.storage[key] = value
}

// NewBlockContext creates an empty block context.
func NewBlockContext() *BlockContext {
	return &BlockContext{
		storage: make(map[BlockContextKey]interface{}),
	}
}
