package abci

import (
	"time"

	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"
	tmcmn "github.com/tendermint/tendermint/libs/common"

	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

// ContextType is a context type.
type ContextType uint

const (
	// ContextInitChain is InitChain context.
	ContextInitChain ContextType = iota
	// ContextCheckTx is CheckTx context.
	ContextCheckTx
	// ContextDeliverTx is DeliverTx context.
	ContextDeliverTx
	// ContextBeginBlock is BeginBlock context.
	ContextBeginBlock
	// ContextEndBlock is EndBlock context.
	ContextEndBlock
)

// Context is the context of processing a transaction/block.
type Context struct {
	outputType  ContextType
	data        interface{}
	tags        []tmcmn.KVPair
	currentTime time.Time
	state       *ApplicationState
}

// NewContext creates a new Context of the given type.
func NewContext(outputType ContextType, now time.Time, state *ApplicationState) *Context {
	return &Context{
		outputType:  outputType,
		currentTime: now,
		state:       state,
	}
}

// Type returns the type of this output.
func (c *Context) Type() ContextType {
	return c.outputType
}

// Data returns the data to be serialized with this output.
func (c *Context) Data() interface{} {
	return c.data
}

// Tags returns the tags to be passed with this output.
func (c *Context) Tags() []tmcmn.KVPair {
	return c.tags
}

// IsInitChain returns true if this output is part of a InitChain.
func (c *Context) IsInitChain() bool {
	return c.outputType == ContextInitChain
}

// IsCheckOnly returns true if this output is part of a CheckTx.
func (c *Context) IsCheckOnly() bool {
	return c.outputType == ContextCheckTx
}

// EmitData emits data to be serialized as transaction output.
func (c *Context) EmitData(data interface{}) {
	c.data = data
}

// EmitTag emits a key-value tag for the current transaction/block.
func (c *Context) EmitTag(key []byte, value []byte) {
	c.tags = append(c.tags, tmcmn.KVPair{Key: key, Value: value})
}

// GetTag returns a specific tag's value if it exists.
func (c *Context) GetTag(key []byte) []byte {
	return api.GetTag(c.tags, key)
}

// GetEvents returns the ABCI event vector corresponding to the tags.
func (c *Context) GetEvents() []types.Event {
	if len(c.tags) == 0 {
		return nil
	}

	return []types.Event{
		types.Event{
			Type:       api.EventTypeOasis,
			Attributes: c.tags,
		},
	}
}

// Now returns the current tendermint time.
func (c *Context) Now() time.Time {
	return c.currentTime
}

// State returns the mutable state tree.
func (c *Context) State() *iavl.MutableTree {
	if c.IsCheckOnly() {
		return c.state.CheckTxTree()
	}
	return c.state.DeliverTxTree()
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
	sc.ctx.State().ImmutableTree = &sc.ImmutableTree
}
