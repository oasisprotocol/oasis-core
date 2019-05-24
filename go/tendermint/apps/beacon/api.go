package beacon

import "github.com/oasislabs/ekiden/go/tendermint/api"

const (
	// TransactionTag is a unique byte used to identfy transactions
	// for the beacon application.
	TransactionTag byte = 0x04

	// AppName is the ABCI application name.
	// Run before the scheduler application.
	AppName string = "998_beacon"

	// QueryGetBeacon is a path for a Get query.
	QueryGetBeacon string = AppName + "/beacon"
)

var (
	// TagGenerated is an ABCI transaction tag for new beacons.
	// (value is a CBOR serialized beacon.GenerateEvent).
	TagGenerated = []byte("beacon.generated")

	// QueryApp is a query for filtering transactions processed by the
	// beacon application.
	QueryApp = api.QueryForEvent(api.TagApplication, []byte(AppName))
)
