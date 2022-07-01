package api

import (
	"errors"

	tmabcitypes "github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// ErrNoSubscribers is the error returned when publishing a message that noone is subscribed to.
var ErrNoSubscribers = errors.New("no subscribers to given message kind")

// MessageSubscriber is a message subscriber interface.
type MessageSubscriber interface {
	// ExecuteMessage executes a given message.
	ExecuteMessage(ctx *Context, kind, msg interface{}) (interface{}, error)
}

// MessageDispatcher is a message dispatcher interface.
type MessageDispatcher interface {
	// Subscribe subscribes a given message subscriber to messages of a specific kind.
	Subscribe(kind interface{}, ms MessageSubscriber)

	// Publish publishes a message of a given kind by dispatching to all subscribers.
	// Subscribers can return a result, but at most one subscriber should return a
	// non-nil result to any published message. Panics in case more than one subscriber
	// returns a non-nil result.
	//
	// In case there are no subscribers ErrNoSubscribers is returned.
	Publish(ctx *Context, kind, msg interface{}) (interface{}, error)
}

// NoopMessageDispatcher is a no-op message dispatcher that performs no dispatch.
type NoopMessageDispatcher struct{}

// Subscribe implements MessageDispatcher.
func (nd *NoopMessageDispatcher) Subscribe(interface{}, MessageSubscriber) {
}

// Publish implements MessageDispatcher.
func (nd *NoopMessageDispatcher) Publish(*Context, interface{}, interface{}) (interface{}, error) {
	return nil, nil
}

// Application is the interface implemented by multiplexed Oasis-specific
// ABCI applications.
type Application interface {
	MessageSubscriber

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
	OnRegister(ApplicationState, MessageDispatcher)

	// OnCleanup is the function that is called when the ApplicationServer
	// has been halted.
	OnCleanup()

	// ExecuteTx executes a transaction.
	ExecuteTx(*Context, *transaction.Transaction) error

	// InitChain initializes the blockchain with validators and other
	// info from TendermintCore.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	InitChain(*Context, tmabcitypes.RequestInitChain, *genesis.Document) error

	// BeginBlock signals the beginning of a block.
	//
	// Returned tags will be added to the current block.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	BeginBlock(*Context, tmabcitypes.RequestBeginBlock) error

	// EndBlock signals the end of a block, returning changes to the
	// validator set.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	EndBlock(*Context, tmabcitypes.RequestEndBlock) (tmabcitypes.ResponseEndBlock, error)

	// Commit is omitted because Applications will work on a cache of
	// the state bound to the multiplexer.
}
