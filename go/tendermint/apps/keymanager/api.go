// Package keymanager implementes the key manager management applicaiton.
package keymanager

import tmapi "github.com/oasislabs/ekiden/go/tendermint/api"

const (
	// TransactionTag is a unique byte to identify transactions for
	// the key manager application.
	TransactionTag byte = 0x07

	// AppName is the ABCI application name.
	AppName string = "999_keymanager"
)

var (
	// TagStatusUpdate is an ABCI transaction tag for a key manager status
	// update (value is a CBOR serialized key manager status).
	TagStatusUpdate = []byte("keymanager.status")

	// QueryApp is a query for filtering transactions processed by the
	// key manager application.
	QueryApp = tmapi.QueryForEvent([]byte(AppName), tmapi.TagAppNameValue)
)

const (
	// QueryGetStatus is a path for a GetStatus query.
	QueryGetStatus = AppName + "/status"

	// QueryGetStatuses is a path for a GetStatuses query.
	QueryGetStatuses = AppName + "/statuses"
)
