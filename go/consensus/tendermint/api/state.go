package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// ErrNoState is the error returned when state is nil.
var ErrNoState = errors.New("tendermint: no state available (app not registered?)")

// ApplicationState is the overall past, present and future state of all multiplexed applications.
type ApplicationState interface {
	ApplicationQueryState

	// InitialHeight returns the initial height.
	InitialHeight() int64

	// BlockHash returns the last committed block hash.
	BlockHash() []byte

	// ConsensusParameters returns the consensus parameters for the consensus backend itself.
	//
	// These always reflect the active parameters for the current block.
	ConsensusParameters() *consensusGenesis.Parameters

	// BlockContext returns the current block context which can be used
	// to store intermediate per-block results.
	//
	// This method must only be called from BeginBlock/DeliverTx/EndBlock
	// and calls from anywhere else will cause races.
	BlockContext() *BlockContext

	// GetBaseEpoch returns the base epoch.
	GetBaseEpoch() (beacon.EpochTime, error)

	// GetCurrentEpoch returns the epoch at the current block height.
	GetCurrentEpoch(ctx context.Context) (beacon.EpochTime, error)

	// EpochChanged returns true iff the current epoch has changed since the
	// last block.  As a matter of convenience, the current epoch is returned.
	EpochChanged(ctx *Context) (bool, beacon.EpochTime)

	// MinGasPrice returns the configured minimum gas price.
	MinGasPrice() *quantity.Quantity

	// OwnTxSigner returns the transaction signer identity of the local node.
	OwnTxSigner() signature.PublicKey

	// OwnTxSignerAddress returns the transaction signer's staking address of the local node.
	OwnTxSignerAddress() staking.Address

	// Upgrader returns the upgrade backend if available.
	Upgrader() upgrade.Backend

	// NewContext creates a new application processing context.
	NewContext(mode ContextMode, now time.Time) *Context
}

// ApplicationQueryState is minimum methods required to service
// ApplicationState queries.
type ApplicationQueryState interface {
	// Storage returns the storage backend.
	Storage() storage.LocalBackend

	// Checkpointer returns the checkpointer associated with the application state.
	//
	// This may be nil in case checkpoints are disabled.
	Checkpointer() checkpoint.Checkpointer

	// BlockHeight returns the last committed block height.
	BlockHeight() int64

	// GetEpoch returns epoch at block height.
	GetEpoch(ctx context.Context, blockHeight int64) (beacon.EpochTime, error)

	// LastRetainedVersion returns the earliest retained version the ABCI
	// state.
	LastRetainedVersion() (int64, error)
}

// MockApplicationState is the mock application state interface.
type MockApplicationState interface {
	ApplicationState

	// UpdateMockApplicationStateConfig updates the mock application config.
	UpdateMockApplicationStateConfig(cfg *MockApplicationStateConfig)
}

// MockApplicationStateConfig is the configuration for the mock application state.
type MockApplicationStateConfig struct {
	BlockHeight int64
	BlockHash   []byte

	BaseEpoch    beacon.EpochTime
	CurrentEpoch beacon.EpochTime
	EpochChanged bool

	MaxBlockGas transaction.Gas
	MinGasPrice *quantity.Quantity

	OwnTxSigner signature.PublicKey

	Genesis *genesis.Document
}

type mockApplicationState struct {
	cfg *MockApplicationStateConfig

	blockCtx           *BlockContext
	tree               mkvs.Tree
	ownTxSignerAddress staking.Address
}

func (ms *mockApplicationState) Storage() storage.LocalBackend {
	panic("not implemented")
}

func (ms *mockApplicationState) Checkpointer() checkpoint.Checkpointer {
	return nil
}

func (ms *mockApplicationState) InitialHeight() int64 {
	return ms.cfg.Genesis.Height
}

func (ms *mockApplicationState) BlockHeight() int64 {
	return ms.cfg.BlockHeight
}

func (ms *mockApplicationState) BlockHash() []byte {
	return ms.cfg.BlockHash
}

func (ms *mockApplicationState) BlockContext() *BlockContext {
	return ms.blockCtx
}

func (ms *mockApplicationState) GetBaseEpoch() (beacon.EpochTime, error) {
	return ms.cfg.BaseEpoch, nil
}

func (ms *mockApplicationState) GetEpoch(ctx context.Context, blockHeight int64) (beacon.EpochTime, error) {
	return ms.cfg.CurrentEpoch, nil
}

func (ms *mockApplicationState) LastRetainedVersion() (int64, error) {
	return ms.cfg.Genesis.Height, nil
}

func (ms *mockApplicationState) GetCurrentEpoch(ctx context.Context) (beacon.EpochTime, error) {
	return ms.cfg.CurrentEpoch, nil
}

func (ms *mockApplicationState) EpochChanged(ctx *Context) (bool, beacon.EpochTime) {
	return ms.cfg.EpochChanged, ms.cfg.CurrentEpoch
}

func (ms *mockApplicationState) MinGasPrice() *quantity.Quantity {
	return ms.cfg.MinGasPrice
}

func (ms *mockApplicationState) OwnTxSigner() signature.PublicKey {
	return ms.cfg.OwnTxSigner
}

func (ms *mockApplicationState) OwnTxSignerAddress() staking.Address {
	return ms.ownTxSignerAddress
}

func (ms *mockApplicationState) Upgrader() upgrade.Backend {
	return nil
}

func (ms *mockApplicationState) ConsensusParameters() *consensusGenesis.Parameters {
	return &ms.cfg.Genesis.Consensus.Parameters
}

func (ms *mockApplicationState) NewContext(mode ContextMode, now time.Time) *Context {
	c := &Context{
		mode:          mode,
		currentTime:   now,
		gasAccountant: NewNopGasAccountant(),
		state:         ms.tree,
		appState:      ms,
		blockHeight:   ms.cfg.BlockHeight,
		blockCtx:      ms.blockCtx,
		initialHeight: ms.InitialHeight(),
		logger:        logging.GetLogger("consensus/tendermint/abci").With("mode", mode),
	}
	c.Context = context.WithValue(context.Background(), contextKey{}, c)

	return c
}

func (ms *mockApplicationState) UpdateMockApplicationStateConfig(cfg *MockApplicationStateConfig) {
	ms.cfg = cfg

	if cfg.MaxBlockGas > 0 {
		ms.blockCtx.Set(GasAccountantKey{}, NewGasAccountant(cfg.MaxBlockGas))
	} else {
		ms.blockCtx.Set(GasAccountantKey{}, NewNopGasAccountant())
	}

	if cfg.Genesis == nil {
		cfg.Genesis = new(genesis.Document)
	}
	if cfg.Genesis.Height == 0 {
		cfg.Genesis.Height = 1
	}
}

// NewMockApplicationState creates a new mock application state for testing.
func NewMockApplicationState(cfg *MockApplicationStateConfig) MockApplicationState {
	tree := mkvs.New(nil, nil, storage.RootTypeState)

	blockCtx := NewBlockContext()
	m := &mockApplicationState{
		blockCtx:           blockCtx,
		tree:               tree,
		ownTxSignerAddress: staking.NewAddress(cfg.OwnTxSigner),
	}
	m.UpdateMockApplicationStateConfig(cfg)

	return m
}

// ImmutableState is an immutable state wrapper.
type ImmutableState struct {
	mkvs.ImmutableKeyValueTree
}

// CheckContextMode checks if the passed context is an ABCI context and is using one of the
// explicitly allowed modes.
func (s *ImmutableState) CheckContextMode(ctx context.Context, allowedModes []ContextMode) error {
	abciCtx := FromCtx(ctx)
	if abciCtx == nil {
		return fmt.Errorf("abci: method must only be called from ABCI context")
	}

	for _, m := range allowedModes {
		if abciCtx.Mode() == m {
			return nil
		}
	}

	return fmt.Errorf("abci: method cannot be called from the specified ABCI context mode (%s)", abciCtx.Mode())
}

// Close releases the resources associated with the immutable state wrapper.
//
// After calling this method, the immutable state wrapper should not be used anymore.
func (s *ImmutableState) Close() {
	if tree, ok := s.ImmutableKeyValueTree.(mkvs.ClosableTree); ok {
		tree.Close()
	}
}

// NewImmutableState creates a new immutable state wrapper.
func NewImmutableState(ctx context.Context, state ApplicationQueryState, version int64) (*ImmutableState, error) {
	if state == nil {
		return nil, ErrNoState
	}

	// Check if this request was made from an ABCI application context.
	if abciCtx := FromCtx(ctx); abciCtx != nil {
		// Override used state with the one from the current context in the following cases:
		//
		// - If this request was made from InitChain, no blocks and states have been submitted yet.
		// - If this request was made from an ABCI app and is for the current (future) height.
		//
		if abciCtx.IsInitChain() || version == abciCtx.BlockHeight()+1 {
			return &ImmutableState{abciCtx.State()}, nil
		}
	}

	// Handle a regular (external) query where we need to create a new tree.
	if state.BlockHeight() == 0 {
		return nil, consensus.ErrNoCommittedBlocks
	}
	if version <= 0 || version > state.BlockHeight() {
		version = state.BlockHeight()
	}

	ndb := state.Storage().NodeDB()
	roots, err := ndb.GetRootsForVersion(ctx, uint64(version))
	if err != nil {
		return nil, err
	}
	switch len(roots) {
	case 0:
		// No roots for that state -- it may have been pruned.
		return nil, consensus.ErrVersionNotFound
	case 1:
		// A single root.
	default:
		// Unexpected number of roots.
		return nil, fmt.Errorf("state: incorrect number of roots (%d): %+v", version, roots)
	}
	tree := mkvs.NewWithRoot(nil, ndb, roots[0], mkvs.WithoutWriteLog())

	return &ImmutableState{tree}, nil
}
