// Package keymanager implementes the key manager management applicaiton.
package keymanager

import api "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"

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

	// KeyStatusUpdate is an ABCI event attribute key for a key manager
	// status update (value is a CBOR serialized key manager status).
	KeyStatusUpdate = []byte("status")
)
