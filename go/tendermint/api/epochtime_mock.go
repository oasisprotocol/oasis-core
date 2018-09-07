package api

import (
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

const (
	// EpochTimeMockTransactionTag is a unique byte used to identify
	// transactions for the mock epochtime application.
	EpochTimeMockTransactionTag byte = 0x03

	// EpochTimeMockAppName is the ABCI application name.
	EpochTimeMockAppName string = "epochtime_mock"
)

// TagEpochTimeMockEpoch is an ABCI transaction tag for specifying the
// set epoch.
var TagEpochTimeMockEpoch = []byte("epochtime_mock.epoch")

// QueryEpochTimeMockGetEpoch is a path for GetLatestBlock query.
const QueryEpochTimeMockGetEpoch = "epochtime_mock/epoch"

// QueryEpochTimeMockApp is a query for filtering transactions processed by
// the mock epochtime application.
var QueryEpochTimeMockApp = QueryForEvent(TagApplication, []byte(EpochTimeMockAppName))

// TxEpochTimeMock is a transaction to be accepted by the mock epochtime app.
type TxEpochTimeMock struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxSetEpoch `codec:"SetEpoch"`
}

// TxSetEpoch is a transaction for submitting an epoch to be set.
type TxSetEpoch struct {
	Epoch epochtime.EpochTime
}

// QueryGetEpoch is a request for fetching the current epoch.
type QueryGetEpoch struct {
}

// QueryGetEpochResponse is a response to QueryGetEpoch.
type QueryGetEpochResponse struct {
	Epoch  epochtime.EpochTime
	Height int64
}
