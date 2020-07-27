package api

import (
	tmabcitypes "github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

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

	// FireTimer is called within BeginBlock before any other processing
	// takes place for each timer that should fire.
	//
	// Note: Errors are irrecoverable and will result in a panic.
	FireTimer(*Context, *Timer) error

	// Commit is omitted because Applications will work on a cache of
	// the state bound to the multiplexer.
}
