package beacon

import (
	"github.com/tendermint/tendermint/abci/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x40

	// AppName is the ABCI application name.
	// Run before all other applications.
	AppName string = "000_beacon"
)

var (
	// EventType is the ABCI event type for beacon/epoch events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is the query for filtering events procecessed by the
	// beacon application.
	QueryApp = api.QueryForApp(AppName)

	// MethodSetEpoch is the method name for setting epochs.
	MethodSetEpoch = transaction.NewMethodName(AppName, "SetEpoch", beacon.EpochTime(0))

	// Methods is a list of all methods supported by the beacon application.
	Methods = []transaction.MethodName{
		MethodSetEpoch,
		beacon.MethodVRFProve,
	}
)

type internalBackend interface {
	OnInitChain(*api.Context, *beaconState.MutableState, *beacon.ConsensusParameters, *genesis.Document) error
	OnBeginBlock(*api.Context, *beaconState.MutableState, *beacon.ConsensusParameters, types.RequestBeginBlock) error
	ExecuteTx(*api.Context, *beaconState.MutableState, *beacon.ConsensusParameters, *transaction.Transaction) error
}
