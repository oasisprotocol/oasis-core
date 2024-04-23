package api

import (
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// SubcallInfo is the information about a subcall that should be executed.
type SubcallInfo struct {
	// Caller is the address of the caller.
	Caller staking.Address
	// Method is the name of the method that should be invoked.
	Method transaction.MethodName
	// Body is the subcall body.
	Body cbor.RawMessage
}
