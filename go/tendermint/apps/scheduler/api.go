package scheduler

import (
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the scheduler application.
	TransactionTag byte = 0x06

	// AppName is the ABCI application name.
	AppName string = "200_scheduler"

	// QueryAllCommittees is a query path for getting all committees.
	QueryAllCommittees = AppName + "/all-committees"

	// QueryKindsCommittees is a query path for getting the committees of given kinds.
	QueryKindsCommittees = AppName + "/kinds-committees"

	// QueryGetEpoch is a query path for getting current scheduler epoch.
	QueryGetEpoch = AppName + "/epoch"
)

var (
	// TagElected is an ABCI begin block tag with which committee types were elected.
	TagElected = []byte("scheduler.elected")

	// QueryApp is a query for filtering events processed by
	// the scheduler application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)
)
