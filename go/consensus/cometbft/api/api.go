// Package api implements the API between Oasis ABCI application and Oasis core.
package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtquery "github.com/cometbft/cometbft/libs/pubsub/query"
	cmtp2p "github.com/cometbft/cometbft/p2p"
	cmtcrypto "github.com/cometbft/cometbft/proto/tendermint/crypto"
	cmtrpctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

// BackendName is the consensus backend name.
// If changing this, also change the BACKEND_NAME constant in the Rust part at:
// runtime/src/consensus/tendermint/mod.rs.
const BackendName = "tendermint"

const (
	// LogEventPeerExchangeDisabled is a log event that indicates that
	// CometBFT's peer exchange has been disabled.
	LogEventPeerExchangeDisabled = "cometbft/peer_exchange_disabled"
)

// PublicKeyToValidatorUpdate converts an Oasis node public key to a
// CometBFT validator update.
func PublicKeyToValidatorUpdate(id signature.PublicKey, power int64) types.ValidatorUpdate {
	pk, _ := id.MarshalBinary()

	return types.ValidatorUpdate{
		PubKey: cmtcrypto.PublicKey{
			Sum: &cmtcrypto.PublicKey_Ed25519{
				Ed25519: pk,
			},
		},
		Power: power,
	}
}

// NodeToP2PAddr converts an Oasis node descriptor to a CometBFT p2p
// address book entry.
func NodeToP2PAddr(n *node.Node) (*cmtp2p.NetAddress, error) {
	// WARNING: p2p/transport.go:MultiplexTransport.upgrade() uses
	// a case sensitive string comparison to validate public keys,
	// because CometBFT.

	if !n.HasRoles(node.RoleValidator) {
		return nil, fmt.Errorf("cometbft/api: node is not a validator")
	}

	if len(n.Consensus.Addresses) == 0 {
		// Should never happen, but check anyway.
		return nil, fmt.Errorf("cometbft/api: node has no consensus addresses")
	}

	// TODO: Should we extend the function to return more P2P addresses?
	consensusAddr := n.Consensus.Addresses[0]

	pubKey := crypto.PublicKeyToCometBFT(&consensusAddr.ID)
	pubKeyAddrHex := strings.ToLower(pubKey.Address().String())

	coreAddress, _ := consensusAddr.Address.MarshalText()

	addr := pubKeyAddrHex + "@" + string(coreAddress)

	tmAddr, err := cmtp2p.NewNetAddressString(addr)
	if err != nil {
		return nil, fmt.Errorf("cometbft/api: failed to reformat validator: %w", err)
	}

	return tmAddr, nil
}

// EventBuilder is a helper for constructing ABCI events.
type EventBuilder struct {
	app      []byte
	ev       types.Event
	provable []events.Provable
}

// attribute appends a key/value pair to the event.
func (bld *EventBuilder) attribute(key, value string) *EventBuilder {
	bld.ev.Attributes = append(bld.ev.Attributes, types.EventAttribute{
		Key:   key,
		Value: value,
	})

	return bld
}

// TypedAttribute appends a typed attribute to the event.
func (bld *EventBuilder) TypedAttribute(value events.TypedAttribute) *EventBuilder {
	if pv, ok := value.(events.Provable); ok && pv.ShouldProve() {
		bld.provable = append(bld.provable, pv)
	}
	return bld.attribute(value.EventKind(), events.EncodeValue(value))
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
	}
	ev.Attributes = append(ev.Attributes, bld.ev.Attributes...)

	return ev
}

// Provable returns a list of events that are provable.
func (bld *EventBuilder) Provable() []events.Provable {
	return bld.provable
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
	return "oasis_event_" + eventApp
}

// QueryForApp generates a cmtquery.Query for events belonging to the
// specified App.
func QueryForApp(eventApp string) cmtpubsub.Query {
	return cmtquery.MustParse(fmt.Sprintf("%s EXISTS", EventTypeForApp(eventApp)))
}

// BlockMeta is the CometBFT-specific per-block metadata that is
// exposed via the consensus API.
type BlockMeta struct {
	// Header is the CometBFT block header.
	Header *cmttypes.Header `json:"header"`
	// LastCommit is the CometBFT last commit info.
	LastCommit *cmttypes.Commit `json:"last_commit"`
}

// NewBlock creates a new consensus.Block from a CometBFT block.
func NewBlock(blk *cmttypes.Block) *consensus.Block {
	meta := BlockMeta{
		Header:     &blk.Header,
		LastCommit: blk.LastCommit,
	}
	rawMeta := cbor.Marshal(meta)

	var stateRoot hash.Hash
	switch blk.Header.AppHash {
	case nil:
		stateRoot.Empty()
	default:
		if err := stateRoot.UnmarshalBinary(blk.Header.AppHash); err != nil {
			// This should NEVER happen.
			panic(err)
		}
	}

	return &consensus.Block{
		Height: blk.Header.Height,
		Hash:   hash.LoadFromHexBytes(blk.Header.Hash()),
		Time:   blk.Header.Time,
		StateRoot: mkvsNode.Root{
			Version: uint64(blk.Header.Height) - 1,
			Type:    mkvsNode.RootTypeState,
			Hash:    stateRoot,
		},
		Meta: rawMeta,
	}
}

// Backend is a CometBFT consensus backend.
type Backend interface {
	consensus.Backend

	// RegisterApplication registers an ABCI multiplexer application
	// with this service instance and check that its dependencies are
	// registered.
	RegisterApplication(Application) error

	// SetTransactionAuthHandler configures the transaction fee handler for the
	// ABCI multiplexer.
	SetTransactionAuthHandler(TransactionAuthHandler) error

	// GetBlock returns the CometBFT block at the specified height.
	GetCometBFTBlock(ctx context.Context, height int64) (*cmttypes.Block, error)

	// GetBlockResults returns the ABCI results from processing a block
	// at a specific height.
	GetBlockResults(ctx context.Context, height int64) (*cmtrpctypes.ResultBlockResults, error)

	// WatchCometBFTBlocks returns a stream of CometBFT blocks as they are
	// returned via the `EventDataNewBlock` query.
	WatchCometBFTBlocks() (<-chan *cmttypes.Block, *pubsub.Subscription, error)

	// GetLastRetainedVersion returns the earliest retained version the ABCI
	// state.
	GetLastRetainedVersion(ctx context.Context) (int64, error)

	// Pruner returns the state pruner.
	Pruner() StatePruner
}

// StatePruneHandler is a handler that is called when versions are pruned
// from history.
type StatePruneHandler interface {
	// Prune is called before the specified version is pruned.
	//
	// If an error is returned, pruning is aborted and the version is
	// not pruned from history.
	//
	// Note that this can be called for the same version multiple
	// times (e.g., if one of the handlers fails but others succeed
	// and pruning is later retried).
	Prune(ctx context.Context, version uint64) error
}

// StatePruner is a concrete ABCI mux state pruner implementation.
type StatePruner interface {
	// RegisterHandler registers a prune handler.
	RegisterHandler(handler StatePruneHandler)
}

// TransactionAuthHandler is the interface for ABCI applications that handle
// authenticating transactions (checking nonces and fees).
type TransactionAuthHandler interface {
	consensus.TransactionAuthHandler

	// AuthenticateTx authenticates the given transaction by making sure
	// that the nonce is correct and deducts any fees as specified.
	//
	// It may reject the transaction in case of incorrect nonces, insufficient
	// balance to pay fees or (only during CheckTx) if the gas price is too
	// low.
	//
	// The context may be modified to configure a gas accountant.
	AuthenticateTx(ctx *Context, tx *transaction.Transaction) error

	// PostExecuteTx is called after the transaction has been executed. It is
	// only called in case the execution did not produce an error.
	PostExecuteTx(ctx *Context, tx *transaction.Transaction) error
}

// ServiceEvent is a CometBFT-specific consensus.ServiceEvent.
type ServiceEvent struct {
	Block *cmttypes.EventDataNewBlockHeader `json:"block,omitempty"`
	Tx    *cmttypes.EventDataTx             `json:"tx,omitempty"`
}

// ServiceDescriptor is a CometBFT consensus service descriptor.
type ServiceDescriptor interface {
	// Name returns the name of this service.
	Name() string

	// EventType returns the event type associated with the consensus service.
	EventType() string

	// Queries returns a channel that emits queries that need to be subscribed to.
	Queries() <-chan cmtpubsub.Query

	// Commands returns a channel that emits commands for the service client.
	Commands() <-chan interface{}
}

type serviceDescriptor struct {
	name      string
	eventType string
	queryCh   <-chan cmtpubsub.Query
	cmdCh     <-chan interface{}
}

func (sd *serviceDescriptor) Name() string {
	return sd.name
}

func (sd *serviceDescriptor) EventType() string {
	return sd.eventType
}

func (sd *serviceDescriptor) Queries() <-chan cmtpubsub.Query {
	return sd.queryCh
}

func (sd *serviceDescriptor) Commands() <-chan interface{} {
	return sd.cmdCh
}

// NewServiceDescriptor creates a new consensus service descriptor.
func NewServiceDescriptor(name, eventType string, queryCh <-chan cmtpubsub.Query, cmdCh <-chan interface{}) ServiceDescriptor {
	return &serviceDescriptor{
		name:      name,
		eventType: eventType,
		queryCh:   queryCh,
		cmdCh:     cmdCh,
	}
}

// NewStaticServiceDescriptor creates a new static consensus service descriptor.
func NewStaticServiceDescriptor(name, eventType string, queries []cmtpubsub.Query) ServiceDescriptor {
	ch := make(chan cmtpubsub.Query)
	go func() {
		defer close(ch)

		for _, q := range queries {
			ch <- q
		}
	}()
	return NewServiceDescriptor(name, eventType, ch, nil)
}

// ServiceClient is a consensus service client.
type ServiceClient interface {
	// ServiceDescriptor returns the consensus service descriptor.
	ServiceDescriptor() ServiceDescriptor

	// DeliverBlock delivers a new block.
	//
	// Execution of this method will block delivery of further events.
	DeliverBlock(ctx context.Context, height int64) error

	// DeliverEvent delivers an event emitted by the consensus service.
	DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *types.Event) error

	// DeliverCommand delivers a command emitted via the command channel.
	DeliverCommand(ctx context.Context, height int64, cmd interface{}) error
}

// BaseServiceClient is a default ServiceClient implementation that provides noop implementations of
// all the delivery methods. Implementations should override them as needed.
type BaseServiceClient struct{}

// DeliverBlock implements ServiceClient.
func (bsc *BaseServiceClient) DeliverBlock(ctx context.Context, height int64) error {
	return nil
}

// DeliverEvent implements ServiceClient.
func (bsc *BaseServiceClient) DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *types.Event) error {
	return nil
}

// DeliverCommand implements ServiceClient.
func (bsc *BaseServiceClient) DeliverCommand(ctx context.Context, height int64, cmd interface{}) error {
	return nil
}

type messageKind uint8

// MessageStateSyncCompleted is the message kind for when the node successfully performs a state
// sync. The message itself is nil.
var MessageStateSyncCompleted = messageKind(0)

// CometBFTChainID returns the CometBFT chain ID computed from chain context.
func CometBFTChainID(chainContext string) string {
	return chainContext[:cmttypes.MaxChainIDLen]
}
