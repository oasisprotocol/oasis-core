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
	cmtcoretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
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

// BlockMeta is the CometBFT-specific per-block metadata.
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
		Size: uint64(blk.Size()),
		Meta: rawMeta,
	}
}

// BlockResults are CometBFT-specific consensus block results.
type BlockResults struct {
	// Height contains the block height.
	Height int64 `json:"height"`
	// Meta contains the block results metadata.
	Meta *BlockResultsMeta `json:"meta"`
}

// BlockResultsMeta is the CometBFT-specific per-block results metadata.
type BlockResultsMeta struct {
	TxsResults       []*types.ResponseDeliverTx `json:"txs_results"`
	BeginBlockEvents []types.Event              `json:"begin_block_events"`
	EndBlockEvents   []types.Event              `json:"end_block_events"`
}

// NewBlockResultsMeta converts consensus results into CometBFT-specific block
// results metadata.
func NewBlockResultsMeta(results *consensus.BlockResults) (*BlockResultsMeta, error) {
	var meta BlockResultsMeta
	if err := cbor.Unmarshal(results.Meta, &meta); err != nil {
		return nil, fmt.Errorf("malformed block results metadata: %w", err)
	}

	return &meta, nil
}

// NewBlockResults converts CometBFT-specific block results into consensus results.
func NewBlockResults(results *cmtcoretypes.ResultBlockResults) *consensus.BlockResults {
	meta := BlockResultsMeta{
		TxsResults:       results.TxsResults,
		BeginBlockEvents: results.BeginBlockEvents,
		EndBlockEvents:   results.EndBlockEvents,
	}

	return &consensus.BlockResults{
		Height: results.Height,
		Meta:   cbor.Marshal(meta),
	}
}

// GetBlockResults returns CometBFT-specific block results at the given height.
func GetBlockResults(ctx context.Context, height int64, consensus consensus.Backend) (*BlockResults, error) {
	// Optimize for CometBTF-specific consensus backends.
	if cmt, ok := consensus.(Backend); ok {
		results, err := cmt.GetCometBFTBlockResults(ctx, height)
		if err != nil {
			return nil, err
		}
		return &BlockResults{
			Height: results.Height,
			Meta: &BlockResultsMeta{
				TxsResults:       results.TxsResults,
				BeginBlockEvents: results.BeginBlockEvents,
				EndBlockEvents:   results.EndBlockEvents,
			},
		}, nil

	}

	results, err := consensus.GetBlockResults(ctx, height)
	if err != nil {
		return nil, err
	}
	meta, err := NewBlockResultsMeta(results)
	if err != nil {
		return nil, err
	}

	return &BlockResults{
		Height: results.Height,
		Meta:   meta,
	}, nil
}

// Backend is a CometBFT-specific consensus backend.
type Backend interface {
	// GetCometBFTBlockResults returns the ABCI results from processing a block
	// at a specific height.
	GetCometBFTBlockResults(ctx context.Context, height int64) (*cmtcoretypes.ResultBlockResults, error)
}

// HaltHook is a function that gets called when consensus needs to halt for some reason.
type HaltHook func(ctx context.Context, height int64, epoch beacon.EpochTime, err error)

// TransactionAuthHandler is the interface for ABCI applications that handle
// authenticating transactions (checking nonces and fees).
type TransactionAuthHandler interface {
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
}

type serviceDescriptor struct {
	name      string
	eventType string
	queryCh   <-chan cmtpubsub.Query
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

// NewServiceDescriptor creates a new consensus service descriptor.
func NewServiceDescriptor(name, eventType string, queryCh <-chan cmtpubsub.Query) ServiceDescriptor {
	return &serviceDescriptor{
		name:      name,
		eventType: eventType,
		queryCh:   queryCh,
	}
}

// NewStaticServiceDescriptor creates a new static consensus service descriptor.
func NewStaticServiceDescriptor(name, eventType string, queries []cmtpubsub.Query) ServiceDescriptor {
	ch := make(chan cmtpubsub.Query)
	go func() {
		for _, q := range queries {
			ch <- q
		}
	}()
	return NewServiceDescriptor(name, eventType, ch)
}

// ServiceClient is a consensus service client.
type ServiceClient interface {
	// ServiceDescriptor returns the consensus service descriptor.
	ServiceDescriptor() ServiceDescriptor

	// DeliverHeight delivers a new block height.
	DeliverHeight(ctx context.Context, height int64) error

	// DeliverEvent delivers an event emitted by the consensus service.
	DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *types.Event) error
}

// BaseServiceClient is a default ServiceClient implementation that provides noop implementations of
// all the delivery methods. Implementations should override them as needed.
type BaseServiceClient struct{}

// DeliverHeight implements ServiceClient.
func (bsc *BaseServiceClient) DeliverHeight(context.Context, int64) error {
	return nil
}

// DeliverEvent implements ServiceClient.
func (bsc *BaseServiceClient) DeliverEvent(context.Context, int64, cmttypes.Tx, *types.Event) error {
	return nil
}

type messageKind uint8

var (
	// MessageStateSyncCompleted is the message kind for when the node successfully performs a state
	// sync. The message itself is nil.
	MessageStateSyncCompleted = messageKind(0)

	// MessageExecuteSubcall is the message kind for requesting subcall execution. The message is
	// handled by the multiplexer and should be an instance of SubcallInfo.
	MessageExecuteSubcall = messageKind(1)
)

// CometBFTChainID returns the CometBFT chain ID computed from chain context.
func CometBFTChainID(chainContext string) string {
	return chainContext[:cmttypes.MaxChainIDLen]
}

// ExecutorCommitmentNotifier is an executor commitment notifier interface.
type ExecutorCommitmentNotifier interface {
	// DeliverExecutorCommitment delivers an executor commitment observed
	// in the consensus layer P2P network.
	DeliverExecutorCommitment(runtimeID common.Namespace, ec *commitment.ExecutorCommitment)
}
