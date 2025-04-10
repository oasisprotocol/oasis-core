package api

import (
	"errors"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

// ErrNoSubscribers is the error returned when publishing a message that noone is subscribed to.
var ErrNoSubscribers = errors.New("no subscribers to given message kind")

// MessageSubscriber is a message subscriber interface.
type MessageSubscriber interface {
	// ExecuteMessage executes a given message.
	ExecuteMessage(ctx *Context, kind, msg any) (any, error)
}

// TogglableMessageSubscriber is a message subscriber that can be disabled.
type TogglableMessageSubscriber interface {
	// Enabled checks whether the message subscriber is enabled.
	Enabled(ctx *Context) (bool, error)
}

// MessageDispatcher is a message dispatcher interface.
type MessageDispatcher interface {
	// Subscribe subscribes a given message subscriber to messages of a specific kind.
	Subscribe(kind any, ms MessageSubscriber)

	// Publish publishes a message of a given kind by dispatching to all subscribers.
	// Subscribers can return a result, but at most one subscriber should return a
	// non-nil result to any published message. Panics in case more than one subscriber
	// returns a non-nil result.
	//
	// In case there are no subscribers ErrNoSubscribers is returned.
	Publish(ctx *Context, kind, msg any) (any, error)
}

// NoopMessageDispatcher is a no-op message dispatcher that performs no dispatch.
type NoopMessageDispatcher struct{}

// Subscribe implements MessageDispatcher.
func (nd *NoopMessageDispatcher) Subscribe(any, MessageSubscriber) {
}

// Publish implements MessageDispatcher.
func (nd *NoopMessageDispatcher) Publish(*Context, any, any) (any, error) {
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

	// Subscribe subscribes to messages from other applications.
	Subscribe()

	// OnCleanup is the function that is called when the ApplicationServer
	// has been halted.
	OnCleanup()

	// ExecuteTx executes a transaction.
	ExecuteTx(*Context, *transaction.Transaction) error

	// InitChain initializes the blockchain with validators and other
	// info from CometBFT.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	InitChain(*Context, cmtabcitypes.RequestInitChain, *genesis.Document) error

	// BeginBlock signals the beginning of a block.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	BeginBlock(*Context) error

	// EndBlock signals the end of a block, returning changes to the
	// validator set.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	EndBlock(*Context) (cmtabcitypes.ResponseEndBlock, error)

	// Commit is omitted because Applications will work on a cache of
	// the state bound to the multiplexer.
}

// Extension is the interface implemented by application-specific extensions.
type Extension interface {
	// Methods returns the list of supported methods.
	Methods() []transaction.MethodName

	// ExecuteTx executes a transaction.
	ExecuteTx(*Context, *transaction.Transaction) error

	// InitChain initializes the blockchain with validators and other
	// info from CometBFT.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	InitChain(*Context, cmtabcitypes.RequestInitChain, *genesis.Document) error

	// BeginBlock signals the beginning of a block.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	BeginBlock(*Context) error

	// EndBlock signals the end of a block.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	EndBlock(*Context) error
}

// TogglableApplication is an application that can be disabled.
type TogglableApplication interface {
	// Enabled checks whether the application is enabled.
	Enabled(*Context) (bool, error)
}
