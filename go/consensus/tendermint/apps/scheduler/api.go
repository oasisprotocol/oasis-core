package scheduler

import (
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the scheduler application.
	TransactionTag byte = 0x06

	// AppName is the ABCI application name.
	AppName string = "200_scheduler"
)

var (
	// EventType is the ABCI event type for scheduler events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by the
	// scheduler application.
	QueryApp = api.QueryForApp(AppName)

	// KeyElected is the ABCI event attribute key for the elected
	// committee types.
	KeyElected = []byte("elected")
)
