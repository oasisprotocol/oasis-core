package abci

import (
	"bytes"
	"context"
	"time"

	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
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
type Context struct {
	ctx context.Context

	mode        ContextMode
	currentTime time.Time

	data          interface{}
	events        []types.Event
	gasAccountant GasAccountant

	txSigner signature.PublicKey

	appState    ApplicationState
	state       *iavl.MutableTree
	blockHeight int64
	blockCtx    *BlockContext

	logger *logging.Logger
}

// NewMockContext creates a new mock context for use in tests.
func NewMockContext(mode ContextMode, now time.Time, state *iavl.MutableTree) *Context {
	return &Context{
		ctx:           context.Background(),
		mode:          mode,
		currentTime:   now,
		gasAccountant: NewNopGasAccountant(),
		state:         state,
		blockCtx:      NewBlockContext(),
		logger:        logging.GetLogger("consensus/tendermint/abci").With("mode", mode),
	}
}

// FromCtx extracts an ABCI context from a context.Context if one has been
// set. Otherwise it returns nil.
func FromCtx(ctx context.Context) *Context {
	abciCtx, _ := ctx.Value(contextKey{}).(*Context)
	return abciCtx
}

// Close releases all resources associated with this context.
//
// After calling this method, the context should no longer be used.
func (c *Context) Close() {
	if c.IsSimulation() {
		c.state.Rollback()
	}

	c.events = nil
	c.appState = nil
	c.state = nil
	c.blockCtx = nil
}

// Logger returns the logger associated with this context.
func (c *Context) Logger() *logging.Logger {
	return c.logger
}

// Ctx returns a context.Context that is associated with this ABCI context.
func (c *Context) Ctx() context.Context {
	return c.ctx
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
	default:
		panic("context: only available in transaction context")
	}
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

// EmitData emits data to be serialized as transaction output.
//
// Note: The use of this has mostly been replaced with EmitEvent, please
// think really carefully if you want to use this.
func (c *Context) EmitData(data interface{}) {
	c.data = data
}

// EmitEvent emits an ABCI event for the current transaction/block.
// Note: If the event has no attributes, this routine will do nothing.
func (c *Context) EmitEvent(bld *api.EventBuilder) {
	if bld.Dirty() {
		c.events = append(c.events, bld.Event())
	}
}

// GetEvents returns the ABCI event vector corresponding to the tags.
func (c *Context) GetEvents() []types.Event {
	return c.events
}

// HasEvent checks if a specific event has been emitted.
func (c *Context) HasEvent(evType string, key []byte) bool {
	evType = api.EventTypeForApp(evType)

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

// State returns the mutable state tree.
func (c *Context) State() *iavl.MutableTree {
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

// NewStateCheckpoint creates a new state checkpoint.
func (c *Context) NewStateCheckpoint() *StateCheckpoint {
	return &StateCheckpoint{
		ImmutableTree: *c.State().ImmutableTree,
		ctx:           c,
	}
}

// StateCheckpoint is a state checkpoint that can be used to rollback state.
type StateCheckpoint struct {
	iavl.ImmutableTree

	ctx *Context
}

// Close releases resources associated with the checkpoint.
func (sc *StateCheckpoint) Close() {
	sc.ctx = nil
}

// Rollback rolls back the active state to the one from the checkpoint.
func (sc *StateCheckpoint) Rollback() {
	if sc.ctx == nil {
		return
	}
	st := sc.ctx.State()
	st.Rollback()
	st.ImmutableTree = &sc.ImmutableTree
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
