// Package api implements the API between Ekiden ABCI application and Ekiden core.
package api

import (
	"bytes"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"
	tmcommon "github.com/tendermint/tendermint/libs/common"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"
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

// TagApplication is an ABCI transaction tag for denoting which application
// processed the given transaction. Value is the given application name.
var TagApplication = []byte("ekiden.app")

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

// GenesisAppState is the encoded ABCI mux genesis application state.
type GenesisAppState struct {
	// ABCIAppState is the per-ABCI application genesis state if any, by
	// ABCI application name.
	ABCIAppState map[string][]byte `json:"abci_app_state,omit_empty"`
}
