package tickermock

import (
	"github.com/oasislabs/ekiden/go/tendermint/api"
	ticker "github.com/oasislabs/ekiden/go/ticker/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the mock ticker application.
	TransactionTag byte = 0x03

	// AppName is the ABCI application name.
	//
	// Note: It must be lexographically before any application that
	// uses time keeping.
	AppName string = "000_ticker_mock"

	// QueryGetTick is a path for GetLatestBlock query.
	QueryGetTick = AppName + "/tick"
)

var (
	// TagTick is an ABCI begin block tag for specifying the set tick.
	TagTick = []byte("tickertime_mock.tick")

	// QueryApp is a query for filtering events processed by
	// the mock epochtime application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)
)

// Tx is a transaction to be accepted by the mock ticker app.
type Tx struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxDoTick `codec:"DoTick"`
}

// TxDoTick is a transaction for triggering a tick.
type TxDoTick struct {
	// Nonce is ued to avoid duplicate DoTick transactions to be ignored by the application.
	Nonce uint64
}

// QueryGetTickResponse is a response to QueryGetTick.
type QueryGetTickResponse struct {
	Tick ticker.TickTime
}
