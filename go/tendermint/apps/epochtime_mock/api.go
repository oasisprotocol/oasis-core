package epochtimemock

import (
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the mock epochtime application.
	TransactionTag byte = 0x03

	// AppName is the ABCI application name.
	//
	// Note: It must be lexographically before any application that
	// uses time keeping.
	AppName string = "000_epochtime_mock"
)

var (
	// EventType is the ABCI event type for mock epochtime events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by
	// the mock epochtime application.
	QueryApp = api.QueryForApp(AppName)

	// KeyEpoch is an ABCI event attribute for specifying the set epoch.
	KeyEpoch = []byte("epoch")
)

// Tx is a transaction to be accepted by the mock epochtime app.
type Tx struct {
	*TxSetEpoch `json:"SetEpoch,omitempty"`
}

// TxSetEpoch is a transaction for submitting an epoch to be set.
type TxSetEpoch struct {
	Epoch epochtime.EpochTime
}
