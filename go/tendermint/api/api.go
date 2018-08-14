// Package api implements the API between Ekiden ABCI application and Ekiden core.
package api

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"
	tmcommon "github.com/tendermint/tendermint/libs/common"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"
	tmcli "github.com/tendermint/tendermint/rpc/client"

	"github.com/oasislabs/ekiden/go/common/cbor"
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

// MarshalTx marshals a CBOR-encodable transaction with given application tag
// prefix.
//
// Messages marshalled using this function can be used as transactions to
// ABCI applications. The application tag must belong to a valid application
// otherwise such a transaction is invalid.
func MarshalTx(tag byte, tx interface{}) []byte {
	message := cbor.Marshal(tx)
	return append([]byte{tag}, message...)
}

// BroadcastTx broadcasts a transaction for Ekiden ABCI application.
//
// The CBOR-encodable transaction together with the given application tag is
// first marshalled and then transmitted using BroadcastTxCommit via the
// given Tendermint client.
func BroadcastTx(client tmcli.Client, tag byte, tx interface{}) error {
	data := MarshalTx(tag, tx)

	response, err := client.BroadcastTxCommit(data)
	if err != nil {
		return errors.Wrap(err, "broadcast tx: commit failed")
	}

	if response.CheckTx.Code != CodeOK.ToInt() {
		return fmt.Errorf("broadcast tx: check tx failed: %s", response.CheckTx.Info)
	}
	if response.DeliverTx.Code != CodeOK.ToInt() {
		return fmt.Errorf("broadcast tx: deliver tx failed: %s", response.DeliverTx.Info)
	}

	return nil
}

// Query transmits a query to the Ekiden ABCI application.
func Query(client tmcli.Client, path string, query interface{}) ([]byte, error) {
	var data []byte
	if query != nil {
		data = cbor.Marshal(query)
	}
	response, err := client.ABCIQuery(path, data)
	if err != nil {
		return nil, errors.Wrap(err, "query: request failed")
	}

	if response.Response.GetCode() != CodeOK.ToInt() {
		return nil, fmt.Errorf("query: failed (code=%s)", Code(response.Response.GetCode()))
	}

	return response.Response.GetValue(), nil
}

// GetTxTag looks up a specific tag in a list of tags and returns its value if any.
//
// When no tag exists it returns nil.
func GetTxTag(tags []tmcommon.KVPair, tag []byte) []byte {
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
