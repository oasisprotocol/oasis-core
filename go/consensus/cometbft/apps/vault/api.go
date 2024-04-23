package vault

import (
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x09

	// AppPriority is the base priority for the app's transactions.
	AppPriority int64 = 5000
)

var (
	// AppName is the ABCI application name.
	AppName = "400_vault"

	// EventType is the ABCI event type for staking events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by the
	// staking application.
	QueryApp = api.QueryForApp(AppName)
)
