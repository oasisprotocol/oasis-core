// Package api provides the implementation agnostic consensus API.
package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// ModuleName is the module name used for error definitions.
	ModuleName = "consensus"

	// HeightLatest is the height that represents the most recent block height.
	HeightLatest int64 = 0
)

var (
	// ErrNoCommittedBlocks is the error returned when there are no committed
	// blocks and as such no state can be queried.
	ErrNoCommittedBlocks = errors.New(ModuleName, 1, "consensus: no committed blocks")

	// ErrOversizedTx is the error returned when the given transaction is too big to be processed.
	ErrOversizedTx = errors.New(ModuleName, 2, "consensus: oversized transaction")

	// ErrVersionNotFound is the error returned when the given version (height) cannot be found,
	// possibly because it was pruned.
	ErrVersionNotFound = errors.New(ModuleName, 3, "consensus: version not found")

	// ErrUnsupported is the error returned when the given method is not supported by the consensus
	// backend.
	ErrUnsupported = errors.New(ModuleName, 4, "consensus: method not supported")

	// ErrDuplicateTx is the error returned when the transaction already exists in the mempool.
	ErrDuplicateTx = errors.New(ModuleName, 5, "consensus: duplicate transaction")

	// ErrInvalidArgument is the error returned when the request contains an invalid argument.
	ErrInvalidArgument = errors.New(ModuleName, 6, "consensus: invalid argument")

	// SystemMethods is a map of all system methods.
	SystemMethods = map[transaction.MethodName]struct{}{
		MethodMeta: {},
	}
)

// FeatureMask is the consensus backend feature bitmask.
type FeatureMask uint8

const (
	// FeatureServices indicates support for communicating with consensus services.
	FeatureServices FeatureMask = 1 << 0

	// FeatureFullNode indicates that the consensus backend is independently fully verifying all
	// consensus-layer blocks.
	FeatureFullNode FeatureMask = 1 << 1

	// FeatureArchiveNode indicates that the node is an archive node.
	FeatureArchiveNode FeatureMask = 1 << 2
)

// String returns a string representation of the consensus backend feature bitmask.
func (m FeatureMask) String() string {
	var ret []string
	if m&FeatureServices != 0 {
		ret = append(ret, "consensus services")
	}
	if m&FeatureFullNode != 0 {
		ret = append(ret, "full node")
	}
	if m&FeatureArchiveNode != 0 {
		ret = append(ret, "archive node")
	}

	return strings.Join(ret, ",")
}

// Has checks whether the feature bitmask includes specific features.
func (m FeatureMask) Has(f FeatureMask) bool {
	return m&f != 0
}

// ClientBackend is a consensus interface used by clients that connect to the local full node.
type ClientBackend interface {
	TransactionAuthHandler

	// SubmitTx submits a signed consensus transaction and waits for the transaction to be included
	// in a block. Use SubmitTxNoWait if you only need to broadcast the transaction.
	SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error

	// SubmitTxNoWait submits a signed consensus transaction, but does not wait for the transaction
	// to be included in a block. Use SubmitTx if you need to wait for execution.
	SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error

	// SubmitTxWithProof submits a signed consensus transaction, waits for the transaction to be
	// included in a block and returns a proof of inclusion.
	SubmitTxWithProof(ctx context.Context, tx *transaction.SignedTransaction) (*transaction.Proof, error)

	// StateToGenesis returns the genesis state at the specified block height.
	StateToGenesis(ctx context.Context, height int64) (*genesis.Document, error)

	// EstimateGas calculates the amount of gas required to execute the given transaction.
	EstimateGas(ctx context.Context, req *EstimateGasRequest) (transaction.Gas, error)

	// GetBlock returns a consensus block at a specific height.
	GetBlock(ctx context.Context, height int64) (*Block, error)

	// GetLightBlock returns a light version of the consensus layer block that can be used for light
	// client verification.
	GetLightBlock(ctx context.Context, height int64) (*LightBlock, error)

	// State returns a MKVS read syncer that can be used to read consensus state from a remote node
	// and verify it against the trusted local root.
	State() syncer.ReadSyncer

	// GetParameters returns the consensus parameters for a specific height.
	GetParameters(ctx context.Context, height int64) (*Parameters, error)

	// SubmitEvidence submits evidence of misbehavior.
	SubmitEvidence(ctx context.Context, evidence *Evidence) error

	// GetTransactions returns a list of all transactions contained within a
	// consensus block at a specific height.
	//
	// NOTE: Any of these transactions could be invalid.
	GetTransactions(ctx context.Context, height int64) ([][]byte, error)

	// GetTransactionsWithResults returns a list of transactions and their
	// execution results, contained within a consensus block at a specific
	// height.
	GetTransactionsWithResults(ctx context.Context, height int64) (*TransactionsWithResults, error)

	// GetTransactionsWithProofs returns a list of all transactions and their proofs of inclusion
	// contained within a consensus block at a specific height.
	GetTransactionsWithProofs(ctx context.Context, height int64) (*TransactionsWithProofs, error)

	// GetUnconfirmedTransactions returns a list of transactions currently in the local node's
	// mempool. These have not yet been included in a block.
	GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error)

	// WatchBlocks returns a channel that produces a stream of consensus
	// blocks as they are being finalized.
	WatchBlocks(ctx context.Context) (<-chan *Block, pubsub.ClosableSubscription, error)

	// GetGenesisDocument returns the original genesis document.
	GetGenesisDocument(ctx context.Context) (*genesis.Document, error)

	// GetChainContext returns the chain domain separation context.
	GetChainContext(ctx context.Context) (string, error)

	// GetStatus returns the current status overview.
	GetStatus(ctx context.Context) (*Status, error)

	// GetNextBlockState returns the state of the next block being voted on by validators.
	GetNextBlockState(ctx context.Context) (*NextBlockState, error)

	// Beacon returns the beacon backend.
	Beacon() beacon.Backend

	// Registry returns the registry backend.
	Registry() registry.Backend

	// Staking returns the staking backend.
	Staking() staking.Backend

	// Scheduler returns the scheduler backend.
	Scheduler() scheduler.Backend

	// Governance returns the governance backend.
	Governance() governance.Backend

	// RootHash returns the roothash backend.
	RootHash() roothash.Backend
}

// Block is a consensus block.
//
// While some common fields are provided, most of the structure is dependent on
// the actual backend implementation.
type Block struct {
	// Height contains the block height.
	Height int64 `json:"height"`
	// Hash contains the block header hash.
	Hash hash.Hash `json:"hash"`
	// Time is the second-granular consensus time.
	Time time.Time `json:"time"`
	// StateRoot is the Merkle root of the consensus state tree.
	StateRoot mkvsNode.Root `json:"state_root"`
	// Meta contains the consensus backend specific block metadata.
	Meta cbor.RawMessage `json:"meta"`
}

// NextBlockState has the state of the next block being voted on by validators.
type NextBlockState struct {
	Height int64 `json:"height"`

	NumValidators uint64 `json:"num_validators"`
	VotingPower   uint64 `json:"voting_power"`

	Prevotes   Votes `json:"prevotes"`
	Precommits Votes `json:"precommits"`
}

// Votes are the votes for the next block.
type Votes struct {
	VotingPower uint64  `json:"voting_power"`
	Ratio       float64 `json:"ratio"`
	Votes       []Vote  `json:"votes"`
}

// Vote contains metadata about a vote for the next block.
type Vote struct {
	NodeID        signature.PublicKey `json:"node_id"`
	EntityID      signature.PublicKey `json:"entity_id"`
	EntityAddress staking.Address     `json:"entity_address"`
	VotingPower   uint64              `json:"voting_power"`
}

// StatusState is the concise status state of the consensus backend.
type StatusState uint8

var (
	// StatusStateReady is the ready status state.
	StatusStateReady StatusState
	// StatusStateSyncing is the syncing status state.
	StatusStateSyncing StatusState = 1
	// StatusStateDBLoading is the status state when the database is loading.
	StatusStateDBLoading StatusState = 2
)

// String returns a string representation of a status state.
func (s StatusState) String() string {
	switch s {
	case StatusStateReady:
		return "ready"
	case StatusStateSyncing:
		return "syncing"
	case StatusStateDBLoading:
		return "loading database"
	default:
		return "[invalid status state]"
	}
}

// MarshalText encodes a StatusState into text form.
func (s StatusState) MarshalText() ([]byte, error) {
	switch s {
	case StatusStateReady, StatusStateSyncing, StatusStateDBLoading:
		return []byte(s.String()), nil
	default:
		return nil, fmt.Errorf("invalid StatusState: %d", s)
	}
}

// UnmarshalText decodes a text slice into a StatusState.
func (s *StatusState) UnmarshalText(text []byte) error {
	switch string(text) {
	case StatusStateReady.String():
		*s = StatusStateReady
	case StatusStateSyncing.String():
		*s = StatusStateSyncing
	case StatusStateDBLoading.String():
		*s = StatusStateDBLoading
	default:
		return fmt.Errorf("invalid StatusState: %s", string(text))
	}
	return nil
}

// Status is the current status overview.
type Status struct { // nolint: maligned
	// Status is an concise status of the consensus backend.
	Status StatusState `json:"status"`

	// Version is the version of the consensus protocol that the node is using.
	Version version.Version `json:"version"`
	// Backend is the consensus backend identifier.
	Backend string `json:"backend"`
	// Features are the indicated consensus backend features.
	Features FeatureMask `json:"features"`

	// LatestHeight is the height of the latest block.
	LatestHeight int64 `json:"latest_height"`
	// LatestHash is the hash of the latest block.
	LatestHash hash.Hash `json:"latest_hash"`
	// LatestTime is the timestamp of the latest block.
	LatestTime time.Time `json:"latest_time"`
	// LatestEpoch is the epoch of the latest block.
	LatestEpoch beacon.EpochTime `json:"latest_epoch"`
	// LatestStateRoot is the Merkle root of the consensus state tree.
	LatestStateRoot mkvsNode.Root `json:"latest_state_root"`

	// GenesisHeight is the height of the genesis block.
	GenesisHeight int64 `json:"genesis_height"`
	// GenesisHash is the hash of the genesis block.
	GenesisHash hash.Hash `json:"genesis_hash"`

	// LastRetainedHeight is the height of the oldest retained block.
	LastRetainedHeight int64 `json:"last_retained_height"`
	// LastRetainedHash is the hash of the oldest retained block.
	LastRetainedHash hash.Hash `json:"last_retained_hash"`

	// ChainContext is the chain domain separation context.
	ChainContext string `json:"chain_context"`

	// IsValidator returns whether the current node is part of the validator set.
	IsValidator bool `json:"is_validator"`

	// P2P is the P2P status of the node.
	P2P *P2PStatus `json:"p2p,omitempty"`
}

// P2PStatus is the P2P status of a node.
type P2PStatus struct {
	// PubKey is the public key used for consensus P2P communication.
	PubKey signature.PublicKey `json:"pub_key"`

	// PeerID is the peer ID derived by hashing peer's public key.
	PeerID string `json:"peer_id"`

	// Addresses is a list of configured P2P addresses used when registering the node.
	Addresses []node.ConsensusAddress `json:"addresses"`

	// Peers is a list of node's peers.
	Peers []string `json:"peers"`
}

// Backend is an interface that a consensus backend must provide.
type Backend interface {
	service.BackgroundService
	ServicesBackend

	// SupportedFeatures returns the features supported by this consensus backend.
	SupportedFeatures() FeatureMask

	// Synced returns a channel that is closed once synchronization is
	// complete.
	Synced() <-chan struct{}

	// ConsensusKey returns the consensus signing key.
	ConsensusKey() signature.PublicKey

	// GetAddresses returns the consensus backend addresses.
	GetAddresses() ([]node.ConsensusAddress, error)

	// Checkpointer returns the checkpointer associated with consensus state.
	//
	// This may be nil in case checkpoints are disabled.
	Checkpointer() checkpoint.Checkpointer

	// RegisterP2PService registers the P2P service used for light client state sync.
	RegisterP2PService(p2pAPI.Service) error
}

// HaltHook is a function that gets called when consensus needs to halt for some reason.
type HaltHook func(ctx context.Context, blockHeight int64, epoch beacon.EpochTime, err error)

// ServicesBackend is an interface for consensus backends which indicate support for
// communicating with consensus services.
//
// In case the feature is absent, these methods may return nil or ErrUnsupported.
type ServicesBackend interface {
	ClientBackend

	// RegisterHaltHook registers a function to be called when the consensus needs to halt.
	RegisterHaltHook(hook HaltHook)

	// SubmissionManager returns the transaction submission manager.
	SubmissionManager() SubmissionManager

	// KeyManager returns the keymanager backend.
	KeyManager() keymanager.Backend
}

// TransactionAuthHandler is the interface for handling transaction authentication
// (checking nonces and fees).
type TransactionAuthHandler interface {
	// GetSignerNonce returns the nonce that should be used by the given
	// signer for transmitting the next transaction.
	GetSignerNonce(ctx context.Context, req *GetSignerNonceRequest) (uint64, error)
}

// EstimateGasRequest is a EstimateGas request.
type EstimateGasRequest struct {
	Signer      signature.PublicKey      `json:"signer"`
	Transaction *transaction.Transaction `json:"transaction"`
}

// GetSignerNonceRequest is a GetSignerNonce request.
type GetSignerNonceRequest struct {
	AccountAddress staking.Address `json:"account_address"`
	Height         int64           `json:"height"`
}

// TransactionsWithResults is GetTransactionsWithResults response.
//
// Results[i] are the results of executing Transactions[i].
type TransactionsWithResults struct {
	Transactions [][]byte          `json:"transactions"`
	Results      []*results.Result `json:"results"`
}

// TransactionsWithProofs is GetTransactionsWithProofs response.
//
// Proofs[i] is a proof of block inclusion for Transactions[i].
type TransactionsWithProofs struct {
	Transactions [][]byte `json:"transactions"`
	Proofs       [][]byte `json:"proofs"`
}
