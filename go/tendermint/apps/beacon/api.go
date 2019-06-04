package beacon

import "github.com/oasislabs/ekiden/go/tendermint/api"

const (
	// TransactionTag is a unique byte used to identfy transactions
	// for the beacon application.
	TransactionTag byte = 0x04

	// AppName is the ABCI application name.
	// Run before the scheduler application.
	AppName string = "100_beacon"

	// QueryGetBeacon is a path for a Get query.
	QueryGetBeacon string = AppName + "/beacon"
)

var (
	// TagGenerated is an ABCI begin block tag for new beacons.
	// (value is a CBOR serialized beacon.GenerateEvent).
	TagGenerated = []byte("beacon.generated")

	// QueryBeaconGenerated is a query for filtering blocks where we generated a beacon.
	QueryBeaconGenerated = api.QueryForTag(TagGenerated)
)
