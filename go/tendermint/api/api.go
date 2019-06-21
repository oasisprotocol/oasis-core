// Package api implements the API between Ekiden ABCI application and Ekiden core.
package api

import (
	"bytes"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"
	tmcommon "github.com/tendermint/tendermint/libs/common"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

// Code is a status code for ABCI requests.
type Code uint32

// Status codes for the various ABCI requests.
const (
	CodeOK                 Code = Code(types.CodeTypeOK) // uint32(0)
	CodeInvalidApplication Code = Code(1)
	CodeNoCommittedBlocks  Code = Code(2)
	CodeInvalidFormat      Code = Code(3)
	CodeTransactionFailed  Code = Code(4)
	CodeInvalidQuery       Code = Code(5)
	CodeNotFound           Code = Code(6)
)

// ToInt returns an integer representation of the status code.
func (c Code) ToInt() uint32 {
	return uint32(c)
}

// String returns a string representation of the status code.
func (c Code) String() string {
	switch c {
	case CodeOK:
		return "ok"
	case CodeInvalidApplication:
		return "invalid application"
	case CodeNoCommittedBlocks:
		return "no committed blocks"
	case CodeInvalidFormat:
		return "invalid format"
	case CodeTransactionFailed:
		return "transaction failed"
	case CodeInvalidQuery:
		return "invalid query"
	case CodeNotFound:
		return "not found"
	default:
		return "unknown"
	}
}

// TagAppNameValue is the value that should be used in the `AppName` tag
// used for denoting which application processed the given transaction.
var TagAppNameValue = []byte("1")

// GetTag looks up a specific tag in a list of tags and returns its value if any.
//
// When no tag exists it returns nil.
func GetTag(tags []tmcommon.KVPair, tag []byte) []byte {
	for _, pair := range tags {
		if bytes.Equal(pair.GetKey(), tag) {
			return pair.GetValue()
		}
	}

	return nil
}

// QueryForEvent generates a tmquery.Query for a specific event type.
func QueryForEvent(eventApp []byte, eventType []byte) tmpubsub.Query {
	return tmquery.MustParse(fmt.Sprintf("%s='%s'", eventApp, eventType))
}

type queryTagPresent []byte

func (q queryTagPresent) Matches(tags map[string]string) bool {
	_, ok := tags[string(q)]
	return ok
}

func (q queryTagPresent) String() string {
	return fmt.Sprintf("queryTagPresent(%s)", string(q))
}

// QueryForTag generates a tmquery.Query for events that have a tag with the given key.
func QueryForTag(presentKey []byte) tmpubsub.Query {
	return queryTagPresent(presentKey)
}

// QueryGetByIDRequest is a request for fetching things by ids.
type QueryGetByIDRequest struct {
	ID signature.PublicKey
}

// QueryGetByEpochRequest is a request for fetching things by epoch.
type QueryGetByEpochRequest struct {
	Epoch epochtime.EpochTime
}
