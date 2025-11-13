package stateless

import (
	"container/heap"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"iter"
	"math"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// NewProvider creates a new consensus provider for the stateless client.
func NewProvider(address string, cert *tls.Certificate) (*consensusAPI.Client, error) {
	target, creds, err := createCredentials(address, cert)
	if err != nil {
		return nil, err
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	}

	conn, err := cmnGrpc.Dial(target, opts...)
	if err != nil {
		return nil, err
	}

	return consensusAPI.NewClient(conn), nil
}

func createCredentials(address string, cert *tls.Certificate) (string, credentials.TransportCredentials, error) {
	switch {
	case cmnGrpc.IsSocketAddress(address):
		return address, insecure.NewCredentials(), nil
	case !containsPublicKey(address):
		return address, credentials.NewTLS(&tls.Config{}), nil
	default:
		return createClientCredentials(address, cert)
	}
}

func createClientCredentials(address string, cert *tls.Certificate) (string, credentials.TransportCredentials, error) {
	key, target, _ := strings.Cut(address, "@")

	var pk signature.PublicKey
	if err := pk.UnmarshalText([]byte(key)); err != nil {
		return "", nil, fmt.Errorf("malformed address: %s", address)
	}

	opts := &cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			pk: true,
		},
		Certificates: []tls.Certificate{
			*cert,
		},
	}

	creds, err := cmnGrpc.NewClientCreds(opts)
	if err != nil {
		return "", nil, err
	}

	return target, creds, nil
}

func containsPublicKey(address string) bool {
	return strings.Contains(address, "@")
}

// CompositeProvider routes consensus requests to the most suitable provider
// based on dynamic scoring.
type CompositeProvider struct {
	scorer *providerScorer
	logger *logging.Logger
}

// NewCompositeProvider creates a new composite consensus provider
// for the stateless client.
func NewCompositeProvider(providers []consensusAPI.Backend) *CompositeProvider {
	return &CompositeProvider{
		scorer: newProviderScorer(providers),
		logger: logging.GetLogger("cometbft/stateless/provider"),
	}
}

// EstimateGas implements consensusAPI.Backend.
func (p *CompositeProvider) EstimateGas(ctx context.Context, req *consensusAPI.EstimateGasRequest) (transaction.Gas, error) {
	var gas transaction.Gas

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if gas, err = provider.EstimateGas(ctx, req); err != nil {
			p.logger.Warn("failed to estimate gas", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas from any provider: %w", err)
	}

	return gas, nil
}

// GetBlock implements consensusAPI.Backend.
func (p *CompositeProvider) GetBlock(ctx context.Context, height int64) (*consensusAPI.Block, error) {
	var blk *consensusAPI.Block

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if blk, err = provider.GetBlock(ctx, height); err != nil {
			p.logger.Warn("failed to get block", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get block from any provider: %w", err)
	}

	return blk, nil
}

// GetBlockResults implements consensusAPI.Backend.
func (p *CompositeProvider) GetBlockResults(ctx context.Context, height int64) (*consensusAPI.BlockResults, error) {
	var res *consensusAPI.BlockResults

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if res, err = provider.GetBlockResults(ctx, height); err != nil {
			p.logger.Warn("failed to get block results", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get block results from any provider: %w", err)
	}

	return res, nil
}

// GetChainContext implements consensusAPI.Backend.
func (p *CompositeProvider) GetChainContext(ctx context.Context) (string, error) {
	var chainContext string

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if chainContext, err = provider.GetChainContext(ctx); err != nil {
			p.logger.Warn("failed to get chain context", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to get chain context from any provider: %w", err)
	}

	return chainContext, nil
}

// GetGenesisDocument implements consensusAPI.Backend.
func (p *CompositeProvider) GetGenesisDocument(ctx context.Context) (*genesis.Document, error) {
	var doc *genesis.Document

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if doc, err = provider.GetGenesisDocument(ctx); err != nil {
			p.logger.Warn("failed to get genesis document", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get genesis document from any provider: %w", err)
	}

	return doc, nil
}

// GetLastRetainedHeight implements consensusAPI.Backend.
func (p *CompositeProvider) GetLastRetainedHeight(ctx context.Context) (int64, error) {
	var height int64

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if height, err = provider.GetLastRetainedHeight(ctx); err != nil {
			p.logger.Warn("failed to get last retained height", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get last retained height from any provider: %w", err)
	}

	return height, nil
}

// GetLatestHeight implements consensusAPI.Backend.
func (p *CompositeProvider) GetLatestHeight(ctx context.Context) (int64, error) {
	var height int64

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if height, err = provider.GetLatestHeight(ctx); err != nil {
			p.logger.Warn("failed to get latest height", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get latest height from any provider: %w", err)
	}

	return height, nil
}

// GetLightBlock implements consensusAPI.Backend.
func (p *CompositeProvider) GetLightBlock(ctx context.Context, height int64) (*consensusAPI.LightBlock, error) {
	var lb *consensusAPI.LightBlock

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if lb, err = provider.GetLightBlock(ctx, height); err != nil {
			p.logger.Warn("failed to get light block", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get light block from any provider: %w", err)
	}

	return lb, nil
}

// GetValidators implements consensusAPI.Backend.
func (p *CompositeProvider) GetValidators(ctx context.Context, height int64) (*consensusAPI.Validators, error) {
	var validators *consensusAPI.Validators

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if validators, err = provider.GetValidators(ctx, height); err != nil {
			p.logger.Warn("failed to get validators", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get validators from any provider: %w", err)
	}

	return validators, nil
}

// GetNextBlockState implements consensusAPI.Backend.
func (p *CompositeProvider) GetNextBlockState(ctx context.Context) (*consensusAPI.NextBlockState, error) {
	var state *consensusAPI.NextBlockState

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if state, err = provider.GetNextBlockState(ctx); err != nil {
			p.logger.Warn("failed to get next block state", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get next block state from any provider: %w", err)
	}

	return state, nil
}

// GetParameters implements consensusAPI.Backend.
func (p *CompositeProvider) GetParameters(ctx context.Context, height int64) (*consensusAPI.Parameters, error) {
	var params *consensusAPI.Parameters

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if params, err = provider.GetParameters(ctx, height); err != nil {
			p.logger.Warn("failed to get parameters", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get parameters from any provider: %w", err)
	}

	return params, nil
}

// GetSignerNonce implements consensusAPI.Backend.
func (p *CompositeProvider) GetSignerNonce(ctx context.Context, req *consensusAPI.GetSignerNonceRequest) (uint64, error) {
	var nonce uint64

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if nonce, err = provider.GetSignerNonce(ctx, req); err != nil { //nolint:staticcheck // Suppress SA1019 deprecation warning
			p.logger.Warn("failed to get signer nonce", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get signer nonce from any provider: %w", err)
	}

	return nonce, nil
}

// GetStatus implements consensusAPI.Backend.
func (p *CompositeProvider) GetStatus(context.Context) (*consensusAPI.Status, error) {
	return nil, fmt.Errorf("not implemented")
}

// GetTransactions implements consensusAPI.Backend.
func (p *CompositeProvider) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	var txs [][]byte

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if txs, err = provider.GetTransactions(ctx, height); err != nil {
			p.logger.Warn("failed to get transactions", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get transactions from any provider: %w", err)
	}

	return txs, nil
}

// GetTransactionsWithProofs implements consensusAPI.Backend.
func (p *CompositeProvider) GetTransactionsWithProofs(ctx context.Context, height int64) (*consensusAPI.TransactionsWithProofs, error) {
	var proofs *consensusAPI.TransactionsWithProofs

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if proofs, err = provider.GetTransactionsWithProofs(ctx, height); err != nil {
			p.logger.Warn("failed to get transactions with proofs", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get transactions with proofs from any provider: %w", err)
	}

	return proofs, nil
}

// GetTransactionsWithResults implements consensusAPI.Backend.
func (p *CompositeProvider) GetTransactionsWithResults(ctx context.Context, height int64) (*consensusAPI.TransactionsWithResults, error) {
	var results *consensusAPI.TransactionsWithResults

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if results, err = provider.GetTransactionsWithResults(ctx, height); err != nil {
			p.logger.Warn("failed to get transactions with results", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get transactions with results from any provider: %w", err)
	}

	return results, nil
}

// GetUnconfirmedTransactions implements consensusAPI.Backend.
func (p *CompositeProvider) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	var txs [][]byte

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if txs, err = provider.GetUnconfirmedTransactions(ctx); err != nil {
			p.logger.Warn("failed to get unconfirmed transactions", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get unconfirmed transactions from any provider: %w", err)
	}

	return txs, nil
}

// MinGasPrice implements consensusAPI.Backend.
func (p *CompositeProvider) MinGasPrice(ctx context.Context) (*quantity.Quantity, error) {
	var price *quantity.Quantity

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if price, err = provider.MinGasPrice(ctx); err != nil {
			p.logger.Warn("failed to get min gas price", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get min gas price from any provider: %w", err)
	}

	return price, nil
}

// State implements consensusAPI.Backend.
func (p *CompositeProvider) State() syncer.ReadSyncer {
	return p
}

// StateToGenesis implements consensusAPI.Backend.
func (p *CompositeProvider) StateToGenesis(ctx context.Context, height int64) (*genesis.Document, error) {
	var doc *genesis.Document

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if doc, err = provider.StateToGenesis(ctx, height); err != nil {
			p.logger.Warn("failed to get state to genesis", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get state to genesis from any provider: %w", err)
	}

	return doc, nil
}

// SubmitEvidence implements consensusAPI.Backend.
func (p *CompositeProvider) SubmitEvidence(ctx context.Context, evidence *consensusAPI.Evidence) error {
	err := p.call(func(provider consensusAPI.Backend) error {
		if err := provider.SubmitEvidence(ctx, evidence); err != nil {
			p.logger.Warn("failed to submit evidence", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to submit evidence to any provider: %w", err)
	}

	return nil
}

// SubmitTx implements consensusAPI.Backend.
func (p *CompositeProvider) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	err := p.call(func(provider consensusAPI.Backend) error {
		if err := provider.SubmitTx(ctx, tx); err != nil {
			p.logger.Warn("failed to submit tx", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to submit tx to any provider: %w", err)
	}

	return nil
}

// SubmitTxNoWait implements consensusAPI.Backend.
func (p *CompositeProvider) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	err := p.call(func(provider consensusAPI.Backend) error {
		if err := provider.SubmitTxNoWait(ctx, tx); err != nil {
			p.logger.Warn("failed to submit tx no wait", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to submit tx no wait to any provider: %w", err)
	}

	return nil
}

// SubmitTxWithProof implements consensusAPI.Backend.
func (p *CompositeProvider) SubmitTxWithProof(ctx context.Context, tx *transaction.SignedTransaction) (*transaction.Proof, error) {
	var proof *transaction.Proof

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if proof, err = provider.SubmitTxWithProof(ctx, tx); err != nil {
			p.logger.Warn("failed to submit tx with proof", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit tx with proof to any provider: %w", err)
	}

	return proof, nil
}

// WatchBlocks implements consensusAPI.Backend.
func (p *CompositeProvider) WatchBlocks(ctx context.Context) (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)
	ch := make(chan *consensusAPI.Block)

	// fetchBlock tries to get a block at the given height, with retries.
	fetchBlock := func(ctx context.Context, height int64) (*consensusAPI.Block, error) {
		backoff := cmnBackoff.NewExponentialBackOff()

		for {
			blk, err := p.GetBlock(ctx, height)
			switch err {
			case nil:
				return blk, nil
			default:
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff.NextBackOff()):
			}
		}
	}

	// fillBlocks tries to get and emit blocks in the given range [start, end).
	fillBlocks := func(ctx context.Context, start int64, end int64) error {
		for height := start; height < end; height++ {
			blk, err := fetchBlock(ctx, height)
			if err != nil {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- blk:
			}
		}

		return nil
	}

	// watchBlocks tries to subscribe to blocks from one of the providers, with retries.
	watchBlocks := func() (<-chan *consensusAPI.Block, pubsub.ClosableSubscription, error) {
		backoff := cmnBackoff.NewExponentialBackOff()

		var (
			ch  <-chan *consensusAPI.Block
			sub pubsub.ClosableSubscription
		)

		for {
			err := p.call(func(provider consensusAPI.Backend) error {
				var err error
				if ch, sub, err = provider.WatchBlocks(ctx); err != nil {
					p.logger.Warn("failed to watch blocks", "err", err)
					return err
				}
				return nil
			})
			switch err {
			case nil:
				return ch, sub, nil
			default:
			}

			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff.NextBackOff()):
			}
		}
	}

	nextHeight := int64(math.MaxInt64)

	// streamBlocks tries to stream blocks from one of the providers.
	streamBlocks := func(ctx context.Context) error {
		blkCh, blkSub, err := watchBlocks()
		if err != nil {
			return err
		}
		defer blkSub.Close()

		for blk := range blkCh {
			if blk.Height < nextHeight && nextHeight != math.MaxInt64 {
				continue
			}
			if err := fillBlocks(ctx, nextHeight, blk.Height); err != nil {
				return err
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- blk:
				nextHeight = blk.Height + 1
			}

		}

		return fmt.Errorf("block channel closed")
	}

	go func() {
		defer close(ch)

		for {
			if err := streamBlocks(ctx); err != nil {
				if err == ctx.Err() {
					return
				}
				p.logger.Warn("failed to stream blocks: %w", err)
			}
		}
	}()

	return ch, sub, nil
}

// SyncGet implements syncer.ReadSyncer.
func (p *CompositeProvider) SyncGet(ctx context.Context, req *syncer.GetRequest) (*syncer.ProofResponse, error) {
	var rsp *syncer.ProofResponse

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if rsp, err = provider.State().SyncGet(ctx, req); err != nil {
			p.logger.Warn("failed to sync get", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sync get from any provider: %w", err)
	}

	return rsp, nil
}

// SyncGetPrefixes implements syncer.ReadSyncer.
func (p *CompositeProvider) SyncGetPrefixes(ctx context.Context, req *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	var rsp *syncer.ProofResponse

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if rsp, err = provider.State().SyncGetPrefixes(ctx, req); err != nil {
			p.logger.Warn("failed to sync get prefixes", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sync get prefixes from any provider: %w", err)
	}

	return rsp, nil
}

// SyncIterate implements syncer.ReadSyncer.
func (p *CompositeProvider) SyncIterate(ctx context.Context, req *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	var rsp *syncer.ProofResponse

	err := p.call(func(provider consensusAPI.Backend) error {
		var err error
		if rsp, err = provider.State().SyncIterate(ctx, req); err != nil {
			p.logger.Warn("failed to sync iterate", "err", err)
			return err
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sync iterate from any provider: %w", err)
	}

	return rsp, nil
}

// call applies the given function to each provider in order of ranking until
// one call succeeds.
func (p *CompositeProvider) call(f func(provider consensusAPI.Backend) error) error {
	var errs error

	for provider := range p.scorer.topProviders() {
		if err := f(provider); err != nil {
			errs = errors.Join(errs, err)
			p.scorer.resetScore(provider)
			continue
		}
		p.scorer.boostScore(provider)
		return nil
	}

	return errs
}

// providerScorer ranks providers based on their current scores.
type providerScorer struct {
	mu     sync.Mutex
	scores map[consensusAPI.Backend]*providerScore
	queue  providerScoreHeap
}

// newProviderScorer creates a new provider scorer.
func newProviderScorer(providers []consensusAPI.Backend) *providerScorer {
	scores := make(map[consensusAPI.Backend]*providerScore)
	for _, provider := range providers {
		scores[provider] = &providerScore{
			provider: provider,
		}
	}

	queue := make(providerScoreHeap, 0, len(scores))
	for _, score := range scores {
		score.index = len(queue)
		queue = append(queue, score)
	}

	return &providerScorer{
		scores: scores,
		queue:  queue,
	}
}

// topProviders returns a sequence of providers ordered by their current scores,
// from highest to lowest.
func (s *providerScorer) topProviders() iter.Seq[consensusAPI.Backend] {
	// Make a deep copy to prevent popping from affecting the original queue.
	s.mu.Lock()
	queue := make(providerScoreHeap, 0, len(s.queue))
	for _, s := range s.queue {
		score := &providerScore{
			provider: s.provider,
			value:    s.value,
			index:    s.index,
		}
		queue = append(queue, score)
	}
	s.mu.Unlock()

	return func(yield func(consensusAPI.Backend) bool) {
		for queue.Len() > 0 {
			score := heap.Pop(&queue).(*providerScore)
			if !yield(score.provider) {
				return
			}
		}
	}
}

// resetScore sets the score of the given provider to zero.
func (s *providerScorer) resetScore(provider consensusAPI.Backend) {
	s.mu.Lock()
	defer s.mu.Unlock()

	score, ok := s.scores[provider]
	if !ok {
		return
	}
	score.value = 0
	heap.Fix(&s.queue, score.index)
}

// boostScore increments the score of the given provider.
func (s *providerScorer) boostScore(provider consensusAPI.Backend) {
	s.mu.Lock()
	defer s.mu.Unlock()

	score, ok := s.scores[provider]
	if !ok {
		return
	}
	if score.value == math.MaxInt {
		return
	}
	score.value++
	heap.Fix(&s.queue, score.index)
}

// score returns the current score of the given provider.
func (s *providerScorer) score(provider consensusAPI.Backend) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	score, ok := s.scores[provider]
	if !ok {
		return 0
	}
	return score.value
}

// providerScore represents the score of a single provider.
type providerScore struct {
	provider consensusAPI.Backend
	value    int
	index    int
}

// providerScoreHeap is a max-heap of provider scores.
type providerScoreHeap []*providerScore

func (h providerScoreHeap) Len() int {
	return len(h)
}

func (h providerScoreHeap) Less(i, j int) bool {
	return h[i].value > h[j].value
}

func (h providerScoreHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *providerScoreHeap) Push(x any) {
	n := len(*h)
	score := x.(*providerScore)
	score.index = n
	*h = append(*h, score)
}

func (h *providerScoreHeap) Pop() any {
	old := *h
	n := len(old)
	score := old[n-1]
	old[n-1] = nil
	*h = old[0 : n-1]
	return score
}
