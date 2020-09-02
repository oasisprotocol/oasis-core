package api

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var _ Backend = (*BaseBackend)(nil)

// BaseBackend is a consensus backend that supports no features and panics for all methods.
type BaseBackend struct {
}

// Implements Backend.
func (b *BaseBackend) Name() string {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Start() error {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Stop() {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Quit() <-chan struct{} {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Cleanup() {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) SupportedFeatures() FeatureMask {
	return FeatureMask(0)
}

// Implements Backend.
func (b *BaseBackend) Synced() <-chan struct{} {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) ConsensusKey() signature.PublicKey {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetAddresses() ([]node.ConsensusAddress, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) RegisterHaltHook(func(ctx context.Context, blockHeight int64, epoch epochtime.EpochTime)) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) SubmitEvidence(ctx context.Context, evidence *Evidence) error {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) SubmissionManager() SubmissionManager {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) EpochTime() epochtime.Backend {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Beacon() beacon.Backend {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) KeyManager() keymanager.Backend {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Registry() registry.Backend {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) RootHash() roothash.Backend {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Staking() staking.Backend {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) Scheduler() scheduler.Backend {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) StateToGenesis(ctx context.Context, height int64) (*genesis.Document, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) EstimateGas(ctx context.Context, req *EstimateGasRequest) (transaction.Gas, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) WaitEpoch(ctx context.Context, epoch epochtime.EpochTime) error {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetEpoch(ctx context.Context, height int64) (epochtime.EpochTime, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetBlock(ctx context.Context, height int64) (*Block, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetTransactionsWithResults(ctx context.Context, height int64) (*TransactionsWithResults, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) WatchBlocks(ctx context.Context) (<-chan *Block, pubsub.ClosableSubscription, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetGenesisDocument(ctx context.Context) (*genesis.Document, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetStatus(ctx context.Context) (*Status, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetSignerNonce(ctx context.Context, req *GetSignerNonceRequest) (uint64, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetLightBlock(ctx context.Context, height int64) (*LightBlock, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) GetParameters(ctx context.Context, height int64) (*Parameters, error) {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) State() syncer.ReadSyncer {
	panic(ErrUnsupported)
}

// Implements Backend.
func (b *BaseBackend) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	panic(ErrUnsupported)
}
