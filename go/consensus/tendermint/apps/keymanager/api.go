// Package keymanager implements the key manager management application.
package keymanager

import api "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x07

	// AppName is the ABCI application name.
	AppName string = "999_keymanager"
)

var (
	// EventType is the ABCI event type for key manager events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering transactions processed by the
	// key manager application.
	QueryApp = api.QueryForApp(AppName)
)
