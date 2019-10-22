package beacon

import "github.com/oasislabs/oasis-core/go/tendermint/api"

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the beacon application.
	TransactionTag byte = 0x04

	// AppName is the ABCI application name.
	// Run before the scheduler application.
	AppName string = "100_beacon"
)

var (
	// TagGenerated is an ABCI begin block tag for new beacons.
	// (value is a CBOR serialized beacon.GenerateEvent).
	TagGenerated = []byte("beacon.generated")

	// QueryApp is a query for filtering events processed by the
	// beacon application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)
)
