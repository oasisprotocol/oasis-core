// Package api implements the API between Oasis ABCI application and Oasis core.
package api

import (
	"fmt"
	"strings"

	"github.com/tendermint/tendermint/abci/types"
	tmcmn "github.com/tendermint/tendermint/libs/common"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmquery "github.com/tendermint/tendermint/libs/pubsub/query"
	tmp2p "github.com/tendermint/tendermint/p2p"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
)

// BackendName is the consensus backend name.
const BackendName = "tendermint"

const (
	// LogEventPeerExchangeDisable is a log event that indicates that
	// Tendermint's peer exchange has been disabled.
	LogEventPeerExchangeDisabled = "tendermint/peer_exchange_disabled"
)

var tagAppNameValue = []byte("1")

// VotingPower is the default voting power for all validator nodes.
const VotingPower = 1

// PublicKeyToValidatorUpdate converts an Oasis node public key to a
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

// NodeToP2PAddr converts an Oasis node descriptor to a tendermint p2p
// address book entry.
func NodeToP2PAddr(n *node.Node) (*tmp2p.NetAddress, error) {
	// WARNING: p2p/transport.go:MultiplexTransport.upgrade() uses
	// a case sensitive string comparison to validate public keys,
	// because tendermint.

	if !n.HasRoles(node.RoleValidator) {
		return nil, fmt.Errorf("tendermint/api: node is not a validator")
	}

	if len(n.Consensus.Addresses) == 0 {
		// Should never happen, but check anyway.
		return nil, fmt.Errorf("tendermint/api: node has no consensus addresses")
	}

	// TODO: Should we extend the function to return more P2P addresses?
	consensusAddr := n.Consensus.Addresses[0]

	pubKey := crypto.PublicKeyToTendermint(&consensusAddr.ID)
	pubKeyAddrHex := strings.ToLower(pubKey.Address().String())

	coreAddress, _ := consensusAddr.Address.MarshalText()

	addr := pubKeyAddrHex + "@" + string(coreAddress)

	tmAddr, err := tmp2p.NewNetAddressString(addr)
	if err != nil {
		return nil, fmt.Errorf("tendermint/api: failed to reformat validator: %w", err)
	}

	return tmAddr, nil
}

const eventTypeOasis = "oasis"

// EventBuilder is a helper for constructing ABCI events.
type EventBuilder struct {
	app []byte
	ev  types.Event
}

// Attribute appends a key/value pair to the event.
func (bld *EventBuilder) Attribute(key, value []byte) *EventBuilder {
	bld.ev.Attributes = append(bld.ev.Attributes, tmcmn.KVPair{
		Key:   key,
		Value: value,
	})

	return bld
}

// Dirty returns true iff the EventBuilder has attributes.
func (bld *EventBuilder) Dirty() bool {
	return len(bld.ev.Attributes) > 0
}

// Event returns the event from the EventBuilder.
func (bld *EventBuilder) Event() types.Event {
	// Return a copy to support emitting incrementally.
	ev := types.Event{
		Type: bld.ev.Type,
		Attributes: []tmcmn.KVPair{
			tmcmn.KVPair{
				Key:   []byte("updated"),
				Value: tagAppNameValue,
			},
		},
	}
	ev.Attributes = append(ev.Attributes, bld.ev.Attributes...)

	return ev
}

// NewEventBuilder returns a new EventBuilder for the given ABCI app.
func NewEventBuilder(app string) *EventBuilder {
	return &EventBuilder{
		app: []byte(app),
		ev: types.Event{
			Type: EventTypeForApp(app),
		},
	}
}

// EventTypeForApp generates the ABCI event type for events belonging
// to the specified App.
func EventTypeForApp(eventApp string) string {
	return eventTypeOasis + "." + eventApp
}

// QueryForApp generates a tmquery.Query for events belonging to the
// specified App.
func QueryForApp(eventApp string) tmpubsub.Query {
	return tmquery.MustParse(fmt.Sprintf("%s.updated='%s'", EventTypeForApp(eventApp), tagAppNameValue))
}
