package governance

import (
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x08

	// AppName is the ABCI application name.
	AppName string = "300_governance"
)

var (
	// EventType is the ABCI event type for governance events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering transactions processed by the
	// governance application.
	QueryApp = api.QueryForApp(AppName)

	// KeyProposalSubmitted is an ABCI event attribute key for submitted
	// proposals (value is a CBOR serialized ProposalSubmittedEvent).
	KeyProposalSubmitted = []byte("proposal-submitted")
	// KeyVote is an ABCI event attribute key for submitted votes (value is a
	// CBOR serialized VoteEvent).
	KeyVote = []byte("vote")
	// KeyProposalFinalized is an ABCI event attribute key for finalized
	// proposals (value is a CBOR serialized ProposalFinalizedEvent).
	KeyProposalFinalized = []byte("proposal-finalized")
	// KeyProposalExecuted is an ABCI event attribute key for executed proposals
	// (value is a CBOR serialized ProposalExecutedEvent).
	KeyProposalExecuted = []byte("proposal-executed")
)
