package staking

import (
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x05

	// AppPriority is the base priority for the app's transactions.
	AppPriority int64 = 1000
)

var (
	// AppName is the ABCI application name.
	AppName = stakingState.AppName

	// EventType is the ABCI event type for staking events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by the
	// staking application.
	QueryApp = api.QueryForApp(AppName)
)
