package governance

import (
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x08

	// AppName is the ABCI application name.
	AppName string = "300_governance"

	// AppPriority is the base priority for the app's transactions.
	AppPriority int64 = 25000
)

var (
	// EventType is the ABCI event type for governance events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering transactions processed by the
	// governance application.
	QueryApp = api.QueryForApp(AppName)
)
