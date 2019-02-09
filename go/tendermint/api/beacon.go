package api

const (
	// BeaconTransactionTag is a unique byte used to identfy transactions
	// for the beacon application.
	BeaconTransactionTag byte = 0x04

	// BeaconAppName is the ABCI application name.
	BeaconAppName string = "999_beacon"

	// QueryBeaconGetBeacon is a path for a Get query.
	QueryBeaconGetBeacon string = BeaconAppName + "/beacon"
)

var (
	// TagBeaconGenerated is an ABCI transaction tag for new beacons.
	// (value is a CBOR serialized beacon.GenerateEvent).
	TagBeaconGenerated = []byte("beacon.generated")

	// QueryBeaconApp is a query for filtering transactions processed
	// by the beacon application.
	QueryBeaconApp = QueryForEvent(TagApplication, []byte(BeaconAppName))
)
