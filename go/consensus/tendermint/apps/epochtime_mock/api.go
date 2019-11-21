package epochtimemock

import (
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x03

	// AppName is the ABCI application name.
	//
	// Note: It must be lexographically before any application that
	// uses time keeping.
	AppName string = "000_epochtime_mock"
)

var (
	// EventType is the ABCI event type for mock epochtime events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by
	// the mock epochtime application.
	QueryApp = api.QueryForApp(AppName)

	// KeyEpoch is an ABCI event attribute for specifying the set epoch.
	KeyEpoch = []byte("epoch")

	// MethodSetEpoch is the method name for setting epochs.
	MethodSetEpoch = transaction.NewMethodName(AppName, "SetEpoch", epochtime.EpochTime(0))

	// Methods is a list of all methods supported by the epochtime mock application.
	Methods = []transaction.MethodName{
		MethodSetEpoch,
	}
)
