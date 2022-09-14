package registry

import (
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x01

	// AppName is the ABCI application name.
	AppName string = "200_registry"

	// AppPriority is the base priority for the app's transactions.
	AppPriority int64 = 50000
)

var (
	// EventType is the ABCI event type for registry events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by
	// the registry application.
	QueryApp = api.QueryForApp(AppName)
)
