package staking

import (
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x05
)

var (
	// AppName is the ABCI application name.
	AppName = stakingState.AppName

	//EventType is the ABCI event type for staking events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by the
	// staking application.
	QueryApp = api.QueryForApp(AppName)

	// KeyTakeEscrow is an ABCI event attribute key for TakeEscrow calls
	// (value is an api.TakeEscrowEvent).
	KeyTakeEscrow = stakingState.KeyTakeEscrow

	// KeyReclaimEscrow is an ABCI event attribute key for ReclaimEscrow
	// calls (value is an api.ReclaimEscrowEvent).
	KeyReclaimEscrow = []byte("reclaim_escrow")

	// KeyTransfer is an ABCI event attribute key for Transfers (value is
	// an api.TransferEvent).
	KeyTransfer = stakingState.KeyTransfer

	// KeyBurn is an ABCI event attribute key for Burn calls (value is
	// an api.BurnEvent).
	KeyBurn = []byte("burn")

	// KeyAddEscrow is an ABCI event attribute key for AddEscrow calls
	// (value is an api.AddEscrowEvent).
	KeyAddEscrow = stakingState.KeyAddEscrow
)
