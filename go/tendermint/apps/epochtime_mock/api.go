package epochtimemock

import (
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/tendermint/api"
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

	// QueryGetEpoch is a path for GetLatestBlock query.
	QueryGetEpoch = AppName + "/epoch"
)

var (
	// TagEpoch is an ABCI begin block tag for specifying the set epoch.
	TagEpoch = []byte("epochtime_mock.epoch")

	// QueryEpochChange is a query for filtering blocks where we changed the epoch.
	QueryEpochChange = api.QueryForTag(TagEpoch)
)

// Tx is a transaction to be accepted by the mock epochtime app.
type Tx struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxSetEpoch `codec:"SetEpoch"`
}

// TxSetEpoch is a transaction for submitting an epoch to be set.
type TxSetEpoch struct {
	Epoch epochtime.EpochTime
}

// QueryGetEpochResponse is a response to QueryGetEpoch.
type QueryGetEpochResponse struct {
	Epoch  epochtime.EpochTime
	Height int64
}
