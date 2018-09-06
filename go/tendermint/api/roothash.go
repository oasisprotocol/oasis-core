package api

import (
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
)

const (
	// RootHashTransactionTag is a unique byte used to identify
	// transactions for the root hash application.
	RootHashTransactionTag byte = 0x02

	// RootHashAppName is the ABCI application name.
	RootHashAppName string = "roothash"
)

var (
	// TagRootHashUpdate is an ABCI transaction tag for marking transactions
	// which have been processed by roothash (value is TagRootHashUpdateValue).
	TagRootHashUpdate = []byte("roothash.update")
	// TagRootHashUpdateValue is the only allowed value for TagRootHashUpdate.
	TagRootHashUpdateValue = []byte("1")

	// TagRootHashCommit is an ABCI transaction tag for new commit
	// submissions (value is commit hash).
	TagRootHashCommit = []byte("roothash.commit")

	// TagRootHashDiscrepancyDetected is an ABCI transaction tag for
	// discrepancy detected events (value is input batch hash).
	TagRootHashDiscrepancyDetected = []byte("roothash.discrepancy")

	// TagRootHashRoundFailed is an ABCI transaction tag for round
	// failure events (value is failure reason).
	TagRootHashRoundFailed = []byte("roothash.round_failed")

	// TagRootHashFinalized is an ABCI transaction tag for finalized
	// blocks (value is serialized block header).
	TagRootHashFinalized = []byte("roothash.finalized")
	// TagRootHashFinalizedRound is an ABCI transaction tag for finalized
	// blocks (value is round number as string).
	TagRootHashFinalizedRound = []byte("roothash.finalized_round")

	// TagRootHashID is an ABCI transaction tag for specifying the
	// contract ID.
	TagRootHashID = []byte("roothash.id")
)

const (
	// QueryRootHashGetLatestBlock is a path for GetLatestBlock query.
	QueryRootHashGetLatestBlock = "roothash/block"
)

var (
	// QueryRootHashApp is a query for filtering transactions processed by
	// the root hash application.
	QueryRootHashApp = QueryForEvent(TagApplication, []byte(RootHashAppName))

	// QueryRootHashUpdate is a query for filtering transactions where root
	// hash application state has been updated. This is required as state
	// can change as part of foreign application transactions.
	QueryRootHashUpdate = QueryForEvent(TagRootHashUpdate, TagRootHashUpdateValue)
)

// TxRootHash is a transaction to be accepted by the roothash app.
type TxRootHash struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxCommit `codec:"Commit"`
}

// TxCommit is a transaction for submitting a roothash commitment.
type TxCommit struct {
	ID         signature.PublicKey
	Commitment roothash.Commitment
}

// QueryGetLatestBlock is a request for fetching the latest block.
type QueryGetLatestBlock struct {
	ID signature.PublicKey
}
