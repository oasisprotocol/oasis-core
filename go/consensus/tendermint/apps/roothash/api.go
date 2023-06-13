package roothash

import (
	"fmt"

	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtquery "github.com/cometbft/cometbft/libs/pubsub/query"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x02

	// AppName is the ABCI application name.
	AppName string = "999_roothash"

	// AppPriority is the base priority for the app's transactions.
	AppPriority int64 = 15000
)

var (
	// EventType is the ABCI event type for roothash events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering transactions processed by the
	// roothash application.
	QueryApp = api.QueryForApp(AppName)
)

// QueryForRuntime returns a query for filtering transactions processed by the roothash application
// limited to a specific runtime.
func QueryForRuntime(runtimeID common.Namespace) cmtpubsub.Query {
	ev := roothash.RuntimeIDAttribute{ID: runtimeID}
	return cmtquery.MustParse(fmt.Sprintf("%s AND %s.%s='%s'", QueryApp, EventType, ev.EventKind(), ev.EventValue()))
}
