package stateless

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/beacon"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/consensus"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto/merkle"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/full"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/registry"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	stakingAPI "github.com/oasisprotocol/oasis-core/go/staking/api"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	// stateRootCacheCapacity is the capacity of the state root LRU cache.
	stateRootCacheCapacity = 128

	// resultsHashCacheCapacity is the capacity of the results hash LRU cache.
	resultsHashCacheCapacity = 128
)

// Core is a stateless implementation of consensus backend.
type Core struct {
	chainContext  string
	genesisHeight int64
	genesis       genesisAPI.Provider

	provider    consensusAPI.Backend
	lightClient *light.Client

	beaconQuerier    beacon.QueryFactory
	consensusQuerier consensus.QueryFactory
	registryQuerier  registry.QueryFactory

	stateRootCache   *lru.Cache
	resultsHashCache *lru.Cache

	blockNotifier *pubsub.Broker

	startWatchingBlocksCh   chan struct{}
	startWatchingBlocksOnce sync.Once

	mu          sync.Mutex
	latestBlock *consensusAPI.Block

	logger *logging.Logger
}

// NewCore creates a new stateless consensus backend.
//
// After construction, queriers must be set before using the instance.
func NewCore(provider consensusAPI.Backend, lightClient *light.Client, cfg Config) *Core {
	return &Core{
		chainContext:          cfg.ChainContext,
		genesisHeight:         cfg.GenesisHeight,
		genesis:               cfg.Genesis,
		provider:              provider,
		lightClient:           lightClient,
		stateRootCache:        lru.New(lru.Capacity(stateRootCacheCapacity, false)),
		resultsHashCache:      lru.New(lru.Capacity(resultsHashCacheCapacity, false)),
		blockNotifier:         pubsub.NewBroker(true),
		startWatchingBlocksCh: make(chan struct{}),
		logger:                logging.GetLogger("cometbft/stateless/core"),
	}
}

// SetQueriers sets consensus and registry queriers.
func (c *Core) SetQueriers(beaconQuerier beacon.QueryFactory, consensusQuerier consensus.QueryFactory, registryQuerier registry.QueryFactory) {
	c.beaconQuerier = beaconQuerier
	c.consensusQuerier = consensusQuerier
	c.registryQuerier = registryQuerier
}

// EstimateGas implements api.Backend.
func (c *Core) EstimateGas(ctx context.Context, req *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	// The gas estimate cannot be verified without simulating the transaction.
	// Therefore, callers must ensure that the returned value falls within
	// the acceptable limit.
	return c.provider.EstimateGas(ctx, req)
}

// GetBlock implements api.Backend.
func (c *Core) GetBlock(ctx context.Context, height int64) (*consensusAPI.Block, error) {
	lb, err := c.lightBlock(ctx, height)
	if err != nil {
		return nil, err
	}

	blk, err := c.provider.GetBlock(ctx, lb.Height)
	if err != nil {
		return nil, err
	}

	if err = verifyBlock(blk, lb); err != nil {
		return nil, err
	}

	return blk, nil
}

// GetBlockResults implements api.Backend.
func (c *Core) GetBlockResults(ctx context.Context, height int64) (*consensusAPI.BlockResults, error) {
	lb, err := c.lightBlock(ctx, height)
	if err != nil {
		return nil, err
	}

	results, err := c.provider.GetBlockResults(ctx, lb.Height)
	if err != nil {
		return nil, err
	}

	if _, err = c.verifyBlockResults(ctx, results, lb); err != nil {
		return nil, err
	}

	return results, nil
}

// GetChainContext implements api.Backend.
func (c *Core) GetChainContext(context.Context) (string, error) {
	// Local chain context is considered trustworthy.
	return c.chainContext, nil
}

// GetGenesisDocument implements api.Backend.
func (c *Core) GetGenesisDocument(context.Context) (*genesisAPI.Document, error) {
	// Local genesis document is considered trustworthy.
	return c.genesis.GetGenesisDocument()
}

// GetLastRetainedHeight implements api.Backend.
func (c *Core) GetLastRetainedHeight(ctx context.Context) (int64, error) {
	// The last retained height equals to the last retained light client height
	// as this is the oldest height stateless client can verify the data against.
	return c.lightClient.FirstTrustedHeight()
}

// GetLatestHeight implements api.Backend.
func (c *Core) GetLatestHeight(ctx context.Context) (int64, error) {
	lb, err := c.lightBlock(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return 0, err
	}
	return lb.Height, nil
}

// GetLightBlock implements api.Backend.
func (c *Core) GetLightBlock(ctx context.Context, height int64) (*consensusAPI.LightBlock, error) {
	lb, err := c.lightBlock(ctx, height)
	if err != nil {
		return nil, err
	}
	return light.EncodeLightBlock(lb)
}

// GetValidators implements api.Backend.
func (c *Core) GetValidators(ctx context.Context, height int64) (*consensusAPI.Validators, error) {
	lb, err := c.lightBlock(ctx, height)
	switch err {
	case nil:
		return light.EncodeValidators(lb.ValidatorSet, lb.Height)
	default:
	}

	// If the requested height is not yet available (i.e., in the future),
	// try to fetch the validators manually and verify them against
	// the previous light block.
	if height < 2 {
		return nil, consensusAPI.ErrVersionNotFound
	}

	lb, err = c.lightBlock(ctx, height-1)
	if err != nil {
		return nil, err
	}

	validators, err := c.provider.GetValidators(ctx, height)
	if err != nil {
		return nil, err
	}

	if err = c.verifyNextValidators(validators, lb); err != nil {
		return nil, err
	}

	return validators, nil
}

// GetNextBlockState implements api.Backend.
func (c *Core) GetNextBlockState(ctx context.Context) (*consensusAPI.NextBlockState, error) {
	lb, err := c.lightBlock(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return nil, err
	}

	nbs := &consensusAPI.NextBlockState{
		Height:        lb.Height,
		NumValidators: uint64(lb.ValidatorSet.Size()),
		VotingPower:   uint64(lb.ValidatorSet.TotalVotingPower()),
	}

	query, err := c.registryQuerier.QueryAt(ctx, lb.Height)
	if err != nil {
		return nil, fmt.Errorf("failed to query registry: %w", err)
	}

	for i, val := range lb.ValidatorSet.Validators {
		vote := consensusAPI.Vote{
			VotingPower: uint64(val.VotingPower),
		}

		valNode, err := query.NodeByConsensusAddress(ctx, val.Address)
		switch err {
		case nil:
			vote.NodeID = valNode.ID
			vote.EntityID = valNode.EntityID
			vote.EntityAddress = stakingAPI.NewAddress(valNode.EntityID)
		default:
		}

		// Skipping pre-votes as they are not accessible.

		if precommit := lb.Commit.GetVote(int32(i)); precommit != nil {
			nbs.Precommits.Votes = append(nbs.Precommits.Votes, vote)
			nbs.Precommits.VotingPower = nbs.Precommits.VotingPower + vote.VotingPower
		}
	}
	nbs.Precommits.Ratio = float64(nbs.Precommits.VotingPower) / float64(nbs.VotingPower)

	return nbs, nil
}

// GetParameters implements api.Backend.
func (c *Core) GetParameters(ctx context.Context, height int64) (*consensusAPI.Parameters, error) {
	lb, err := c.lightBlock(ctx, height)
	if err != nil {
		return nil, err
	}

	params, err := c.provider.GetParameters(ctx, lb.Height)
	if err != nil {
		return nil, err
	}

	if err = c.verifyParameters(ctx, params, lb); err != nil {
		return nil, err
	}

	return params, nil
}

// GetSignerNonce implements api.Backend.
func (c *Core) GetSignerNonce(context.Context, *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	// Deprecated and will be removed in the future.
	return 0, fmt.Errorf("not implemented")
}

// GetStatus implements api.Backend.
func (c *Core) GetStatus(ctx context.Context) (*consensusAPI.Status, error) {
	query, err := c.beaconQuerier.QueryAt(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("failed to query beacon: %w", err)
	}
	epoch, _, err := query.Epoch(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch epoch: %w", err)
	}

	status := &consensusAPI.Status{
		Status:             consensusAPI.StatusStateReady,
		Version:            version.ConsensusProtocol,
		Backend:            api.BackendName,
		Features:           consensusAPI.FeatureServices,
		LatestEpoch:        epoch,
		GenesisHeight:      c.genesisHeight,
		GenesisHash:        hash.Hash{}, // Blocks so far in the past cannot be fetched.
		LastRetainedHeight: 0,           // No state.
		LastRetainedHash:   hash.Hash{}, // No state.
		ChainContext:       c.chainContext,
		IsValidator:        false,
		P2P:                &consensusAPI.P2PStatus{}, // Cannot be queried from the core.
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.latestBlock != nil {
		status.LatestHeight = c.latestBlock.Height
		status.LatestHash = c.latestBlock.Hash
		status.LatestTime = c.latestBlock.Time
		status.LatestStateRoot = c.latestBlock.StateRoot
		status.LatestBlockSize = c.latestBlock.Size
	}

	return status, nil
}

// GetTransactions implements api.Backend.
func (c *Core) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	lb, err := c.lightBlock(ctx, height)
	if err != nil {
		return nil, err
	}

	txs, err := c.provider.GetTransactions(ctx, lb.Height)
	if err != nil {
		return nil, err
	}

	if err := verifyTransactions(txs, lb); err != nil {
		return nil, err
	}

	return txs, nil
}

// GetTransactionsWithProofs implements api.Backend.
func (c *Core) GetTransactionsWithProofs(ctx context.Context, height int64) (*consensusAPI.TransactionsWithProofs, error) {
	txs, err := c.GetTransactions(ctx, height)
	if err != nil {
		return nil, err
	}

	_, proofs := merkle.Proofs(txs)

	return &consensusAPI.TransactionsWithProofs{
		Transactions: txs,
		Proofs:       proofs,
	}, nil
}

// GetTransactionsWithResults implements api.Backend.
func (c *Core) GetTransactionsWithResults(ctx context.Context, height int64) (*consensusAPI.TransactionsWithResults, error) {
	lb, err := c.lightBlock(ctx, height)
	if err != nil {
		return nil, err
	}

	txs, err := c.GetTransactions(ctx, lb.Height)
	if err != nil {
		return nil, err
	}

	results, err := c.provider.GetBlockResults(ctx, lb.Height)
	if err != nil {
		return nil, err
	}

	meta, err := c.verifyBlockResults(ctx, results, lb)
	if err != nil {
		return nil, err
	}

	txResults, err := full.TransactionResultsFromCometBFT(lb.Height, txs, meta.TxsResults)
	if err != nil {
		return nil, err
	}

	return &consensusAPI.TransactionsWithResults{
		Transactions: txs,
		Results:      txResults,
	}, nil
}

// GetUnconfirmedTransactions implements api.Backend.
func (c *Core) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	// Unconfirmed transactions cannot be verified.
	return c.provider.GetUnconfirmedTransactions(ctx)
}

// MinGasPrice implements api.Backend.
func (c *Core) MinGasPrice(ctx context.Context) (*quantity.Quantity, error) {
	q, err := c.consensusQuerier.QueryAt(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("failed to query consensus: %w", err)
	}
	cp, err := q.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	return quantity.NewFromUint64(cp.MinGasPrice), nil
}

// State implements api.Backend.
func (c *Core) State() syncer.ReadSyncer {
	return c.provider.State()
}

// StateToGenesis implements api.Backend.
func (c *Core) StateToGenesis(context.Context, int64) (*genesisAPI.Document, error) {
	// Not supported due to the high computational and network overhead.
	return nil, consensusAPI.ErrUnsupported
}

// SubmitEvidence implements api.Backend.
func (c *Core) SubmitEvidence(ctx context.Context, evidence *consensusAPI.Evidence) error {
	return c.provider.SubmitEvidence(ctx, evidence)
}

// SubmitTx implements api.Backend.
func (c *Core) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	return c.provider.SubmitTx(ctx, tx)
}

// SubmitTxNoWait implements api.Backend.
func (c *Core) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return c.provider.SubmitTxNoWait(ctx, tx)
}

// SubmitTxWithProof implements api.Backend.
func (c *Core) SubmitTxWithProof(ctx context.Context, tx *transaction.SignedTransaction) (*transaction.Proof, error) {
	proof, err := c.provider.SubmitTxWithProof(ctx, tx)
	if err != nil {
		return nil, err
	}

	if err = c.verifyProof(ctx, proof, tx); err != nil {
		return nil, err
	}

	return proof, err
}

// WatchBlocks implements api.Backend.
func (c *Core) WatchBlocks(context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	ch := make(chan *consensusAPI.Block)
	sub := c.blockNotifier.Subscribe()
	sub.Unwrap(ch)

	c.startWatchingBlocksOnce.Do(func() {
		close(c.startWatchingBlocksCh)
	})

	return ch, sub, nil
}

// StateRoot implements StateRooter.
func (c *Core) StateRoot(ctx context.Context, height int64) (mkvsNode.Root, error) {
	height, err := c.resolveHeight(ctx, height)
	if err != nil {
		return mkvsNode.Root{}, err
	}

	hash, err := c.stateRoot(ctx, height)
	if err != nil {
		return mkvsNode.Root{}, err
	}

	return mkvsNode.Root{
		Version: uint64(height),
		Type:    mkvsNode.RootTypeState,
		Hash:    hash,
	}, nil
}

// Serve listens for new blocks and notifies subscribers when requested.
func (c *Core) Serve(ctx context.Context) error {
	c.logger.Info("started")

	if err := c.serve(ctx); err != nil {
		c.logger.Error("stopped", "err", err)
		return err
	}

	return nil
}

func (c *Core) serve(ctx context.Context) error {
	if err := c.watchBlocks(ctx); err != nil {
		return fmt.Errorf("block watcher stopped: %w", err)
	}

	return nil
}

func (c *Core) watchBlocks(ctx context.Context) error {
	select {
	case <-c.startWatchingBlocksCh:
	case <-ctx.Done():
		return ctx.Err()
	}

	c.logger.Info("watching blocks")

	ch, sub, err := c.provider.WatchBlocks(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return fmt.Errorf("block channel closed")
			}

			if err := c.handleNewBlock(ctx, blk); err != nil {
				return fmt.Errorf("failed to handle new block: %w", err)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Core) handleNewBlock(ctx context.Context, blk *consensusAPI.Block) error {
	c.logger.Info("new block", "height", blk.Height)

	lb, err := c.retryLightBlock(ctx, blk.Height)
	if err != nil {
		return fmt.Errorf("failed to fetch light block: %w", err)
	}

	if err := verifyBlock(blk, lb); err != nil {
		return fmt.Errorf("failed to verify block: %w", err)
	}

	c.blockNotifier.Broadcast(blk)

	c.mu.Lock()
	c.latestBlock = blk
	c.mu.Unlock()

	return nil
}

func verifyBlock(blk *consensusAPI.Block, lb *cmttypes.LightBlock) error {
	if blk.Height != lb.Height {
		return fmt.Errorf("mismatched block height")
	}
	if blk.Hash != hash.LoadFromHexBytes(lb.Header.Hash()) {
		return fmt.Errorf("mismatched block hash")
	}
	if blk.Time.UTC() != lb.Header.Time.UTC().Truncate(time.Second) {
		return fmt.Errorf("mismatched block time")
	}
	var namespace common.Namespace
	if blk.StateRoot.Namespace != namespace {
		return fmt.Errorf("mismatched block state root namespace")
	}
	if blk.StateRoot.Version != uint64(lb.Height)-1 {
		return fmt.Errorf("mismatched block state root version")
	}
	if blk.StateRoot.Type != mkvsNode.RootTypeState {
		return fmt.Errorf("mismatched block state root type")
	}
	if !bytes.Equal(blk.StateRoot.Hash[:], lb.Header.AppHash) {
		return fmt.Errorf("mismatched block state root hash")
	}
	// Block size cannot be verified.

	var meta api.BlockMeta
	if err := cbor.Unmarshal(blk.Meta, &meta); err != nil {
		return fmt.Errorf("malformed block meta: %w", err)
	}

	header, err := lb.Header.ToProto().Marshal()
	if err != nil {
		return fmt.Errorf("malformed block meta header: %w", err)
	}
	if !bytes.Equal(meta.Header, header) {
		return fmt.Errorf("mismatched block meta header")
	}

	var lastCommitProto cmtproto.Commit
	if err := lastCommitProto.Unmarshal(meta.LastCommit); err != nil {
		return fmt.Errorf("malformed block meta last commit: %w", err)
	}
	lastCommit, err := cmttypes.CommitFromProto(&lastCommitProto)
	if err != nil {
		return fmt.Errorf("malformed block meta last commit: %w", err)
	}
	if !bytes.Equal(lastCommit.Hash(), lb.LastCommitHash) {
		return fmt.Errorf("mismatched block meta last commit")
	}

	return nil
}

func (c *Core) verifyBlockResults(ctx context.Context, results *consensusAPI.BlockResults, lb *cmttypes.LightBlock) (*api.BlockResultsMeta, error) {
	// TODO: Verify the latest block results once we add LastResultsHash
	// to the system block metadata transaction (#6210).
	lastHeight, err := c.lightClient.LastTrustedHeight()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch last trusted height: %w", err)
	}
	if lastHeight <= lb.Height {
		c.logger.Warn("skipping verification of block results", "height", lb.Height)

		if results.Height != lb.Height {
			return nil, fmt.Errorf("mismatched block height")
		}
		return api.NewBlockResultsMeta(results)
	}

	resultsHash, err := c.resultsHash(ctx, lb.Height)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch results hash: %w", err)
	}

	return verifyBlockResults(results, resultsHash, lb)
}

func verifyBlockResults(results *consensusAPI.BlockResults, resultsHash []byte, lb *cmttypes.LightBlock) (*api.BlockResultsMeta, error) {
	if results.Height != lb.Height {
		return nil, fmt.Errorf("mismatched block height")
	}

	meta, err := api.NewBlockResultsMeta(results)
	if err != nil {
		return nil, err
	}

	hash := cmttypes.NewResults(meta.TxsResults).Hash()
	if !bytes.Equal(hash, resultsHash) {
		return nil, fmt.Errorf("mismatched last results hash")
	}

	// TODO: Verify events once we extend provable events in the system block
	// metadata transaction (#6210).

	return meta, nil
}

func (c *Core) verifyParameters(ctx context.Context, params *consensusAPI.Parameters, lb *cmttypes.LightBlock) error {
	if params.Height != lb.Height {
		return fmt.Errorf("mismatched block height")
	}

	var pb cmtproto.ConsensusParams
	if err := pb.Unmarshal(params.Meta); err != nil {
		return fmt.Errorf("malformed parameters: %w", err)
	}
	cmtparams := cmttypes.ConsensusParamsFromProto(pb)
	if err := cmtparams.ValidateBasic(); err != nil {
		return err
	}
	if !bytes.Equal(cmtparams.Hash(), lb.ConsensusHash) {
		return fmt.Errorf("mismatched consensus parameters hash")
	}

	q, err := c.consensusQuerier.QueryAt(ctx, lb.Height)
	if err != nil {
		return fmt.Errorf("failed to query consensus: %w", err)
	}
	parameters, err := q.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if !bytes.Equal(cbor.Marshal(parameters), cbor.Marshal(params.Parameters)) {
		return fmt.Errorf("mismatched parameters: %w", err)
	}

	return nil
}

func verifyTransactions(txs [][]byte, lb *cmttypes.LightBlock) error {
	var data cmttypes.Data
	for _, tx := range txs {
		data.Txs = append(data.Txs, tx)
	}

	if !bytes.Equal(data.Hash(), lb.DataHash) {
		return fmt.Errorf("failed to verify transactions: hash mismatch")
	}

	return nil
}

func (c *Core) verifyProof(ctx context.Context, proof *transaction.Proof, tx *transaction.SignedTransaction) error {
	stateRoot, err := c.stateRoot(ctx, proof.Height)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(cbor.Marshal(tx))
	if err := merkle.Verify(proof.RawProof, stateRoot[:], hash[:]); err != nil {
		return fmt.Errorf("failed to verify proof: %w", err)
	}

	return nil
}

func (c *Core) verifyNextValidators(validators *consensusAPI.Validators, lb *cmttypes.LightBlock) error {
	if validators.Height != lb.Height+1 {
		return fmt.Errorf("mismatched block height")
	}

	vs, err := light.DecodeValidators(validators)
	if err != nil {
		return err
	}

	if !bytes.Equal(vs.Hash(), lb.NextValidatorsHash.Bytes()) {
		return fmt.Errorf("mismatched next validator set")
	}

	return nil
}

func (c *Core) resolveHeight(ctx context.Context, height int64) (int64, error) {
	if height != consensusAPI.HeightLatest {
		return height, nil
	}

	// If we're watching blocks, the light client should be up to date,
	// so we can use its last trusted height. Otherwise, we need to fetch
	// the latest height manually.
	select {
	case <-c.startWatchingBlocksCh:
		height, err := c.lightClient.LastTrustedHeight()
		if err != nil {
			break
		}
		return height, nil
	default:
	}

	height, err := c.provider.GetLatestHeight(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch latest height: %w", err)
	}
	if height < 1 {
		return 0, fmt.Errorf("invalid height: %d", height)
	}

	return height, nil
}

func (c *Core) lightBlock(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	height, err := c.resolveHeight(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve height: %w", err)
	}

	lb, err := c.lightClient.VerifyLightBlockAt(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("failed to verify light block: %w", err)
	}

	return lb, nil
}

func (c *Core) retryLightBlock(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	var lb *cmttypes.LightBlock

	fetchLightBlock := func() error {
		mlb, err := c.lightBlock(ctx, height)
		if err != nil {
			c.logger.Warn("failed to fetch light block, retrying", "err", err)
			return err
		}
		lb = mlb
		return nil
	}

	bo := backoff.WithContext(cmnBackoff.NewExponentialBackOff(), ctx)
	if err := backoff.Retry(fetchLightBlock, bo); err != nil {
		return nil, err
	}

	return lb, nil
}

func (c *Core) stateRoot(ctx context.Context, height int64) (hash.Hash, error) {
	if stateRoot, ok := c.stateRootCache.Get(height); ok {
		return stateRoot.(hash.Hash), nil
	}

	stateRoot, err := c.fetchStateRoot(ctx, height)
	if err != nil {
		return hash.Hash{}, err
	}

	_ = c.stateRootCache.Put(height, stateRoot)
	return stateRoot, nil
}

func (c *Core) fetchStateRoot(ctx context.Context, height int64) (hash.Hash, error) {
	stateRoot, err := c.fetchStateRootFromLightBlock(ctx, height+1)
	switch err {
	case nil:
		return stateRoot, nil
	default:
	}

	return c.fetchStateRootFromMetaTx(ctx, height)
}

func (c *Core) fetchStateRootFromLightBlock(ctx context.Context, height int64) (hash.Hash, error) {
	lb, err := c.lightClient.VerifyLightBlockAt(ctx, height)
	if err != nil {
		return hash.Hash{}, fmt.Errorf("failed to verify light block: %w", err)
	}

	var h hash.Hash
	if err := h.UnmarshalBinary(lb.AppHash); err != nil {
		return hash.Hash{}, fmt.Errorf("malformed app hash")
	}

	return h, nil
}

func (c *Core) fetchStateRootFromMetaTx(ctx context.Context, height int64) (hash.Hash, error) {
	txs, err := c.GetTransactions(ctx, height)
	if err != nil {
		return hash.Hash{}, err
	}
	return stateRootFromBlockTxs(txs)
}

func stateRootFromBlockTxs(txs [][]byte) (hash.Hash, error) {
	if len(txs) == 0 {
		return hash.Hash{}, fmt.Errorf("malformed block transactions")
	}
	metaTx := txs[len(txs)-1]
	return stateRootFromMetaTx(metaTx)
}

func stateRootFromMetaTx(metaTx []byte) (hash.Hash, error) {
	var sigTx transaction.SignedTransaction
	if err := cbor.Unmarshal(metaTx, &sigTx); err != nil {
		return hash.Hash{}, fmt.Errorf("malformed block metadata transaction: %w", err)
	}
	var tx transaction.Transaction
	if err := cbor.Unmarshal(sigTx.Blob, &tx); err != nil {
		return hash.Hash{}, fmt.Errorf("malformed block metadata transaction: %w", err)
	}
	if tx.Method != consensusAPI.MethodMeta {
		return hash.Hash{}, fmt.Errorf("malformed block metadata transaction: invalid method")
	}
	var meta consensusAPI.BlockMetadata
	if err := cbor.Unmarshal(tx.Body, &meta); err != nil {
		return hash.Hash{}, fmt.Errorf("malformed block metadata transaction: %w", err)
	}
	return meta.StateRoot, nil
}

func (c *Core) resultsHash(ctx context.Context, height int64) ([]byte, error) {
	if hash, ok := c.resultsHashCache.Get(height); ok {
		return hash.([]byte), nil
	}

	hash, err := c.fetchResultsHash(ctx, height)
	if err != nil {
		return nil, err
	}

	_ = c.resultsHashCache.Put(height, hash)
	return hash, nil
}

func (c *Core) fetchResultsHash(ctx context.Context, height int64) ([]byte, error) {
	resultsHash, err := c.fetchResultsHashFromLightBlock(ctx, height+1)
	switch err {
	case nil:
		return resultsHash, nil
	default:
	}

	// TODO: Fetch last results hash once we add LastResultsHash
	// to the system block metadata transaction (#6210).

	return nil, err
}

func (c *Core) fetchResultsHashFromLightBlock(ctx context.Context, height int64) ([]byte, error) {
	lb, err := c.lightClient.VerifyLightBlockAt(ctx, height)
	if err != nil {
		return nil, fmt.Errorf("failed to verify light block: %w", err)
	}

	return lb.LastResultsHash, nil
}
