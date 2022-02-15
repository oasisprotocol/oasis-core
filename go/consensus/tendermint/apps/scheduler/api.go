package scheduler

import (
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x06

	// AppName is the ABCI application name.
	AppName string = "200_scheduler"
)

var (
	// EventType is the ABCI event type for scheduler events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by the
	// scheduler application.
	QueryApp = api.QueryForApp(AppName)
)
