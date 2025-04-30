package beacon

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x40

	// AppName is the ABCI application name.
	// Run before all other applications.
	AppName string = "000_beacon"

	// AppPriority is the base priority for the app's transactions.
	AppPriority int64 = 100000
)

var (
	// EventType is the ABCI event type for beacon/epoch events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is the query for filtering events procecessed by the
	// beacon application.
	QueryApp = api.QueryForApp(AppName)
)

type internalBackend interface {
	OnInitChain(*api.Context, *beaconState.MutableState, *beacon.ConsensusParameters, *genesis.Document) error
	OnBeginBlock(*api.Context, *beaconState.MutableState, *beacon.ConsensusParameters) error
	ExecuteTx(*api.Context, *beaconState.MutableState, *beacon.ConsensusParameters, *transaction.Transaction) error
}
