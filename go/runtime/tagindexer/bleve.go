package tagindexer

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/blevesearch/bleve"
	bleveKeyword "github.com/blevesearch/bleve/analysis/analyzer/keyword"
	"github.com/blevesearch/bleve/index/scorch"
	bleveQuery "github.com/blevesearch/bleve/search/query"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/keyformat"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/runtime/client/api"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
)

const (
	// BleveBackendName is the name of the bleve backend.
	BleveBackendName = "bleve"

	bleveIndexFile = "tag-index.bleve.db"
)

var (
	// txDocIDKeyFmt is the key format used for indexed transaction document IDs.
	txDocIDKeyFmt = keyformat.New('T', uint64(0), &hash.Hash{}, uint32(0))
	// blockDocIDKeyFmt is the key format used for indexed block document IDs.
	blockDocIDKeyFmt = keyformat.New('B', uint64(0))

	// queryByKindBlock is a query matching documents of kind docTypeBlock.
	queryByKindBlock bleveQuery.Query
	// queryByKindTx is a query matching documents of kind docTypeTx.
	queryByKindTx bleveQuery.Query

	_ Backend = (*bleveBackend)(nil)
)

type bleveBackend struct {
	logger *logging.Logger

	index bleve.Index

	blockIndexedNotifier *pubsub.Broker
}

// Common fields.
const (
	fieldKind  = "Kind"
	fieldRound = "Round"
)

// Transaction document fields.
const (
	// docTypeTx is the transaction document type.
	docTypeTx = "tx"

	fieldTxIndex = "TxIndex"
	fieldTags    = "Tags"
)

// txDocument is a transction document in the bleve index.
type txDocument struct {
	// NOTE: Embedding private structs does not work well with reflection.
	ID    string
	Kind  string
	Round uint64

	TxHash  string
	TxIndex uint32
	Tags    map[string][]string
}

func (d txDocument) Type() string {
	return docTypeTx
}

// Block document fields.
const (
	// docTypeBlock is the block document type.
	docTypeBlock = "block"

	fieldBlockHash = "BlockHash"
)

// blockDocument is a block document in the bleve index.
type blockDocument struct {
	// NOTE: Embedding private structs does not work well with reflection.
	ID    string
	Kind  string
	Round uint64

	BlockHash string
}

func (d blockDocument) Type() string {
	return docTypeBlock
}

// queryByRound returns a query matching documents for the given round.
func queryByRound(round uint64) bleveQuery.Query {
	roundF := float64(round)
	inclusive := true
	query := bleve.NewNumericRangeInclusiveQuery(&roundF, &roundF, &inclusive, &inclusive)
	query.SetField(fieldRound)
	return query
}

// queryByTag returns a query matching documents with the given tags.
func queryByTag(key, value []byte) bleveQuery.Query {
	query := bleve.NewTermQuery(string(value))
	query.SetField(fmt.Sprintf("%s.%s", fieldTags, string(key)))
	return query
}

func (b *bleveBackend) Index(
	ctx context.Context,
	round uint64,
	blockHash hash.Hash,
	txs []*transaction.Transaction,
	tags transaction.Tags,
) error {
	// The only reason why a list of transactions needs to be passed is to
	// derive the transaction indices.
	txIndices := make(map[hash.Hash]uint32)
	for idx, tx := range txs {
		txIndices[tx.Hash()] = uint32(idx)
	}

	// Generate documents for transactions.
	txDocs := make(map[hash.Hash]txDocument)
	for _, tag := range tags {
		doc, ok := txDocs[tag.TxHash]
		if !ok {
			doc.Kind = docTypeTx
			doc.ID = string(txDocIDKeyFmt.Encode(round, &tag.TxHash, txIndices[tag.TxHash]))
			doc.Round = round
			doc.TxHash = string(tag.TxHash[:])
			doc.TxIndex = txIndices[tag.TxHash]
			doc.Tags = make(map[string][]string)
		}
		doc.Tags[string(tag.Key)] = append(doc.Tags[string(tag.Key)], string(tag.Value))
		txDocs[tag.TxHash] = doc
	}

	// Generate one document for the block itself.
	var blockDoc blockDocument
	blockDoc.Kind = docTypeBlock
	blockDoc.ID = string(blockDocIDKeyFmt.Encode(round))
	blockDoc.Round = round
	blockDoc.BlockHash = string(blockHash[:])

	batch := b.index.NewBatch()
	for _, txDoc := range txDocs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := batch.Index(txDoc.ID, txDoc); err != nil {
			return err
		}
	}
	if err := batch.Index(blockDoc.ID, blockDoc); err != nil {
		return err
	}

	if err := b.index.Batch(batch); err != nil {
		return err
	}

	b.blockIndexedNotifier.Broadcast(round)

	return nil
}

func (b *bleveBackend) QueryBlock(ctx context.Context, blockHash hash.Hash) (uint64, error) {
	// Filter by block hash.
	qBlockHash := bleve.NewTermQuery(string(blockHash[:]))
	qBlockHash.SetField(fieldBlockHash)

	q := bleve.NewConjunctionQuery(queryByKindBlock, qBlockHash)
	rq := bleve.NewSearchRequest(q)
	rq.Size = 1

	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return 0, err
	}
	if len(result.Hits) == 0 {
		return 0, api.ErrNotFound
	}

	var decRound uint64
	if !blockDocIDKeyFmt.Decode([]byte(result.Hits[0].ID), &decRound) {
		return 0, ErrCorrupted
	}

	return decRound, nil
}

func (b *bleveBackend) QueryTxn(ctx context.Context, key, value []byte) (uint64, hash.Hash, uint32, error) {
	q := bleve.NewConjunctionQuery(queryByKindTx, queryByTag(key, value))
	rq := bleve.NewSearchRequest(q)
	rq.Size = 1

	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return 0, hash.Hash{}, 0, err
	}
	if len(result.Hits) == 0 {
		return 0, hash.Hash{}, 0, api.ErrNotFound
	}

	var decRound uint64
	var decTxHash hash.Hash
	var decTxIndex uint32
	if !txDocIDKeyFmt.Decode([]byte(result.Hits[0].ID), &decRound, &decTxHash, &decTxIndex) {
		return 0, hash.Hash{}, 0, ErrCorrupted
	}

	return decRound, decTxHash, decTxIndex, nil
}

func (b *bleveBackend) QueryTxnByIndex(ctx context.Context, round uint64, index uint32) (hash.Hash, error) {
	// Filter by transaction index.
	inclusive := true
	indexF := float64(index)
	qIndex := bleve.NewNumericRangeInclusiveQuery(&indexF, &indexF, &inclusive, &inclusive)
	qIndex.SetField(fieldTxIndex)

	q := bleve.NewConjunctionQuery(queryByKindTx, queryByRound(round), qIndex)
	rq := bleve.NewSearchRequest(q)
	rq.Size = 1

	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return hash.Hash{}, err
	}
	if len(result.Hits) == 0 {
		return hash.Hash{}, api.ErrNotFound
	}

	var decRound uint64
	var decTxHash hash.Hash
	if !txDocIDKeyFmt.Decode([]byte(result.Hits[0].ID), &decRound, &decTxHash) {
		return hash.Hash{}, ErrCorrupted
	}

	return decTxHash, nil
}

func (b *bleveBackend) QueryTxns(ctx context.Context, query api.Query) (Results, error) {
	qs := []bleveQuery.Query{queryByKindTx}

	// Filter by round.
	var roundMin, roundMax *float64
	if query.RoundMin > 0 {
		r := float64(query.RoundMin)
		roundMin = &r
	}
	if query.RoundMax > 0 {
		r := float64(query.RoundMax)
		roundMax = &r
	}
	if roundMin != nil || roundMax != nil {
		inclusive := true
		qRound := bleve.NewNumericRangeInclusiveQuery(roundMin, roundMax, &inclusive, &inclusive)
		qRound.SetField(fieldRound)
		qs = append(qs, qRound)
	}

	// Filter by key/value tag conditions.
	for _, cond := range query.Conditions {
		switch len(cond.Values) {
		case 0:
			// No values (strange, but ok).
			continue
		case 1:
			// Single value.
			qs = append(qs, queryByTag(cond.Key, cond.Values[0]))
		default:
			// Multiple values.
			var vals []bleveQuery.Query
			for _, v := range cond.Values {
				vals = append(vals, queryByTag(cond.Key, v))
			}
			qs = append(qs, bleve.NewDisjunctionQuery(vals...))
		}
	}

	q := bleve.NewConjunctionQuery(qs...)
	rq := bleve.NewSearchRequest(q)
	if query.Limit > 0 {
		rq.Size = int(query.Limit)
	}
	if rq.Size == 0 || rq.Size > maxQueryLimit {
		rq.Size = maxQueryLimit
	}

	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return nil, err
	}

	results := make(Results)
	for _, hit := range result.Hits {
		var decRound uint64
		var decTxHash hash.Hash
		var decTxIndex uint32
		if !txDocIDKeyFmt.Decode([]byte(hit.ID), &decRound, &decTxHash, &decTxIndex) {
			return nil, ErrCorrupted
		}

		results[decRound] = append(results[decRound], Result{TxHash: decTxHash, TxIndex: decTxIndex})
	}

	return results, nil
}

func (b *bleveBackend) WaitBlockIndexed(ctx context.Context, round uint64) error {
	sub := b.blockIndexedNotifier.Subscribe()
	defer sub.Close()

	ch := make(chan uint64)
	sub.Unwrap(ch)

	q := bleve.NewConjunctionQuery(queryByRound(round))
	rq := bleve.NewSearchRequest(q)
	rq.Size = 1
	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return err
	}
	if len(result.Hits) > 0 {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-ch:
			if r >= round {
				return nil
			}
		}
	}
}

func (b *bleveBackend) Prune(ctx context.Context, round uint64) error {
	rq := bleve.NewSearchRequest(queryByRound(round))
	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return err
	}

	b.logger.Debug("pruning items from index",
		"round", round,
		"item_count", len(result.Hits),
	)

	batch := b.index.NewBatch()
	for _, hit := range result.Hits {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		batch.Delete(hit.ID)
	}

	return b.index.Batch(batch)
}

func (b *bleveBackend) Close() {
	if err := b.index.Close(); err != nil {
		b.logger.Error("failed to close index",
			"err", err,
		)
	}
	b.index = nil
}

func newBleveBackend(dataDir string, runtimeID common.Namespace) (Backend, error) {
	b := &bleveBackend{
		logger:               logging.GetLogger("runtime/history/tagindexer/bleve").With("runtime_id", runtimeID),
		blockIndexedNotifier: pubsub.NewBroker(true),
	}

	mp := bleve.NewIndexMapping()
	mp.DefaultAnalyzer = bleveKeyword.Name
	mp.StoreDynamic = false

	path := filepath.Join(dataDir, bleveIndexFile)
	index, err := bleve.Open(path)
	if err != nil {
		if err != bleve.ErrorIndexPathDoesNotExist {
			return nil, err
		}

		// Create a new index.
		index, err = bleve.NewUsing(path, mp, scorch.Name, scorch.Name, nil)
		if err != nil {
			return nil, err
		}
	}
	b.index = index

	b.logger.Info("initialized tag indexer backend")

	return b, nil
}

// NewBleveBackend creates a new bleve indexer backend factory.
func NewBleveBackend() BackendFactory {
	return newBleveBackend
}

func init() {
	qKindBlock := bleve.NewTermQuery(docTypeBlock)
	qKindBlock.SetField(fieldKind)
	queryByKindBlock = qKindBlock

	qKindTx := bleve.NewTermQuery(docTypeTx)
	qKindTx.SetField(fieldKind)
	queryByKindTx = qKindTx
}
