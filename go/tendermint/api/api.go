// Package api implements the API between Ekiden ABCI application and Ekiden core.
package api

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"
	tmcommon "github.com/tendermint/tendermint/libs/common"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"
	tmp2p "github.com/tendermint/tendermint/p2p"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/tendermint/crypto"
)

// Conesnus Backend Name
const BackendName = "tendermint"

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

// The ABCI event type to denote ABCI mux applications.
const EventTypeEkiden = "ekiden"

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
	return tmquery.MustParse(fmt.Sprintf("%s.%s='%s'", EventTypeEkiden, eventApp, eventType))
}

// QueryGetByIDRequest is a request for fetching things by ids.
type QueryGetByIDRequest struct {
	ID signature.PublicKey
}

// VotingPower is the default voting power for all validator nodes.
const VotingPower = 1

// PublicKeyToValidatorUpdate converts an ekiden node public key to a
// tendermint validator update.
func PublicKeyToValidatorUpdate(id signature.PublicKey, power int64) types.ValidatorUpdate {
	pk, _ := id.MarshalBinary()

	return types.ValidatorUpdate{
		PubKey: types.PubKey{
			Type: types.PubKeyEd25519,
			Data: pk,
		},
		Power: power,
	}
}

// NodeToP2PAddr converts an ekiden node descriptor to a tendermint p2p
// address book entry.
func NodeToP2PAddr(n *node.Node) (*tmp2p.NetAddress, error) {
	// WARNING: p2p/transport.go:MultiplexTransport.upgrade() uses
	// a case senstive string comparsison to validate public keys,
	// because tendermint.

	if !n.HasRoles(node.RoleValidator) {
		return nil, fmt.Errorf("tendermint/api: node is not a validator")
	}

	pubKey := crypto.PublicKeyToTendermint(&n.ID)
	pubKeyAddrHex := strings.ToLower(pubKey.Address().String())

	if len(n.Consensus.Addresses) == 0 {
		// Should never happen, but check anyway.
		return nil, fmt.Errorf("tendermint/api: node has no consensus addresses")
	}
	coreAddress, _ := n.Consensus.Addresses[0].MarshalText()

	addr := pubKeyAddrHex + "@" + string(coreAddress)

	tmAddr, err := tmp2p.NewNetAddressString(addr)
	if err != nil {
		return nil, errors.Wrap(err, "tenderimt/api: failed to reformat validator")
	}

	return tmAddr, nil
}
