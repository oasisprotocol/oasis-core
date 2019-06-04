package indexer

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"

	"github.com/blevesearch/bleve"
	bleveKeyword "github.com/blevesearch/bleve/analysis/analyzer/keyword"
	"github.com/blevesearch/bleve/index/scorch"
	bleveQuery "github.com/blevesearch/bleve/search/query"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/runtime"
)

const (
	// BleveBackendName is the name of the bleve backend.
	BleveBackendName = "bleve"

	bleveIndexFile = "bleve-tag-index.bleve.db"

	docType   = "entry"
	docIDSize = 32 + 8 + 4

	fieldID        = "_id"
	fieldRound     = "round"
	fieldRuntimeID = "runtime_id"
	fieldTxnIndex  = "index"
	fieldTags      = "tags"
)

var (
	_ Backend = (*bleveBackend)(nil)
)

type bleveBackend struct {
	backendCommon

	logger *logging.Logger

	index bleve.Index
}

func encodeID(runtimeID signature.PublicKey, round uint64, index int32) []byte {
	var id [docIDSize]byte
	offset := 0
	// Runtime ID.
	rawRtID, _ := runtimeID.MarshalBinary()
	copy(id[offset:offset+32], rawRtID)
	offset += 32
	// Round.
	binary.LittleEndian.PutUint64(id[offset:offset+8], round)
	offset += 8
	// Transaction index.
	// NOTE: This will underflow for blocks, but that is ok.
	binary.LittleEndian.PutUint32(id[offset:offset+4], uint32(index))

	return id[:]
}

func decodeID(id []byte) (runtimeID signature.PublicKey, round uint64, index int32, err error) {
	if len(id) != docIDSize {
		err = ErrCorrupted
		return
	}

	offset := 0
	// Runtime ID.
	_ = runtimeID.UnmarshalBinary(id[offset : offset+32])
	offset += 32
	// Round.
	round = binary.LittleEndian.Uint64(id[offset : offset+8])
	offset += 8
	// Transaction index.
	index = int32(binary.LittleEndian.Uint32(id[offset : offset+4]))
	return
}

func (b *bleveBackend) Index(ctx context.Context, runtimeID signature.PublicKey, round uint64, tags []runtime.Tag) error {
	docs := make(map[int32]map[string]interface{})

	for _, tag := range tags {
		doc := docs[tag.TxnIndex]
		if doc == nil {
			doc = make(map[string]interface{})
			doc["_type"] = docType
			doc[fieldID] = string(encodeID(runtimeID, round, tag.TxnIndex))
			doc[fieldRuntimeID] = string(runtimeID[:])
			doc[fieldRound] = round
			doc[fieldTxnIndex] = tag.TxnIndex
			doc[fieldTags] = make(map[string][]string)
			docs[tag.TxnIndex] = doc
		}

		tags := doc[fieldTags].(map[string][]string)
		values := tags[string(tag.Key)]
		tags[string(tag.Key)] = append(values, string(tag.Value))
	}

	batch := b.index.NewBatch()
	for _, doc := range docs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := batch.Index(doc[fieldID].(string), doc); err != nil {
			return err
		}
	}

	if err := b.index.Batch(batch); err != nil {
		return err
	}

	b.backendCommon.blockIndexedNotifier.Broadcast(&indexNotification{
		runtimeID: runtimeID,
		round:     round,
	})

	return nil
}

func (b *bleveBackend) QueryBlock(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, error) {
	// Filter by runtime.
	qRuntime := bleve.NewTermQuery(string(runtimeID[:]))
	qRuntime.SetField(fieldRuntimeID)

	// Filter by key/value pair.
	qKV := bleve.NewTermQuery(string(value))
	qKV.SetField(fmt.Sprintf("%s.%s", fieldTags, string(key)))

	// Only return block tags.
	txnIndex := float64(runtime.TagTxnIndexBlock)
	inclusive := true
	qIndex := bleve.NewNumericRangeInclusiveQuery(&txnIndex, &txnIndex, &inclusive, &inclusive)
	qIndex.SetField(fieldTxnIndex)

	q := bleve.NewConjunctionQuery(qRuntime, qKV, qIndex)
	rq := bleve.NewSearchRequest(q)
	rq.Size = 1

	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return 0, err
	}
	if len(result.Hits) == 0 {
		return 0, ErrNotFound
	}

	dRtID, round, _, err := decodeID([]byte(result.Hits[0].ID))
	if err != nil {
		return 0, err
	}
	if !dRtID.Equal(runtimeID) {
		return 0, ErrCorrupted
	}

	return round, nil
}

func (b *bleveBackend) QueryTxn(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (uint64, uint32, error) {
	// Filter by runtime.
	qRuntime := bleve.NewTermQuery(string(runtimeID[:]))
	qRuntime.SetField(fieldRuntimeID)

	// Filter by key/value pair.
	qKV := bleve.NewTermQuery(string(value))
	qKV.SetField(fmt.Sprintf("%s.%s", fieldTags, string(key)))

	// Only return transaction tags.
	txnIndex := 0.0
	qIndex := bleve.NewNumericRangeQuery(&txnIndex, nil)
	qIndex.SetField(fieldTxnIndex)

	q := bleve.NewConjunctionQuery(qRuntime, qKV, qIndex)
	rq := bleve.NewSearchRequest(q)
	rq.Size = 1

	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return 0, 0, err
	}
	if len(result.Hits) == 0 {
		return 0, 0, ErrNotFound
	}

	dRtID, round, index, err := decodeID([]byte(result.Hits[0].ID))
	if err != nil {
		return 0, 0, err
	}
	if !dRtID.Equal(runtimeID) {
		return 0, 0, ErrCorrupted
	}

	return round, uint32(index), nil
}

func (b *bleveBackend) QueryTxns(ctx context.Context, runtimeID signature.PublicKey, query Query) (Results, error) {
	var qs []bleveQuery.Query

	// Filter by runtime.
	qRuntime := bleve.NewTermQuery(string(runtimeID[:]))
	qRuntime.SetField(fieldRuntimeID)
	qs = append(qs, qRuntime)

	// Only return transaction tags.
	txnIndex := 0.0
	qIndex := bleve.NewNumericRangeQuery(&txnIndex, nil)
	qIndex.SetField(fieldTxnIndex)
	qs = append(qs, qIndex)

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
			qKV := bleve.NewTermQuery(string(cond.Values[0]))
			qKV.SetField(fmt.Sprintf("%s.%s", fieldTags, string(cond.Key)))
			qs = append(qs, qKV)
		default:
			// Multiple values.
			var vals []bleveQuery.Query
			for _, v := range cond.Values {
				qKV := bleve.NewTermQuery(string(v))
				qKV.SetField(fmt.Sprintf("%s.%s", fieldTags, string(cond.Key)))
				vals = append(vals, qKV)
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

	results := make(map[uint64][]int32)
	for _, hit := range result.Hits {
		dRtID, round, index, derr := decodeID([]byte(hit.ID))
		if derr != nil {
			return nil, derr
		}
		if !dRtID.Equal(runtimeID) {
			return nil, ErrCorrupted
		}

		results[round] = append(results[round], index)
	}

	return results, nil
}

func (b *bleveBackend) WaitBlockIndexed(ctx context.Context, runtimeID signature.PublicKey, round uint64) error {
	// Filter by runtime.
	qRuntime := bleve.NewTermQuery(string(runtimeID[:]))
	qRuntime.SetField(fieldRuntimeID)

	// Filter by round.
	roundF := float64(round)
	inclusive := true
	qRound := bleve.NewNumericRangeInclusiveQuery(&roundF, &roundF, &inclusive, &inclusive)
	qRound.SetField(fieldRound)

	q := bleve.NewConjunctionQuery(qRuntime, qRound)
	rq := bleve.NewSearchRequest(q)
	rq.Size = 1
	result, err := b.index.SearchInContext(ctx, rq)
	if err != nil {
		return err
	}
	if len(result.Hits) > 0 {
		return nil
	}

	return b.backendCommon.WaitBlockIndexed(ctx, runtimeID, round)
}

func (b *bleveBackend) Prune(ctx context.Context, runtimeID signature.PublicKey, round uint64) error {
	// Filter by runtime.
	qRuntime := bleve.NewTermQuery(string(runtimeID[:]))
	qRuntime.SetField(fieldRuntimeID)

	// Filter by round.
	roundF := float64(round)
	inclusive := true
	qRound := bleve.NewNumericRangeInclusiveQuery(&roundF, &roundF, &inclusive, &inclusive)
	qRound.SetField(fieldRound)

	q := bleve.NewConjunctionQuery(qRuntime, qRound)
	rq := bleve.NewSearchRequest(q)
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

func (b *bleveBackend) Stop() {
	if err := b.index.Close(); err != nil {
		b.logger.Error("failed to close index",
			"err", err,
		)
	}
	b.index = nil
}

// NewBleveBackend creates a new bleve indexer backend.
func NewBleveBackend(dataDir string) (Backend, error) {
	b := &bleveBackend{
		backendCommon: newBackendCommon(),
		logger:        logging.GetLogger("client/indexer/bleveBackend"),
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
