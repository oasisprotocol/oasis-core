package mapp

import (
	"testing"

	tests "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

func TestIncomingMap(t *testing.T) {
	mapp := New(api.Config{
		MaxPoolSize:       10,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 10,
	})
	tests.TxPoolImplementationTests(t, mapp)
}

func BenchmarkIncomingMap(b *testing.B) {
	mapp := New(api.Config{
		MaxPoolSize:       10,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 10,
	})
	tests.TxPoolImplementationBenchmarks(b, mapp)
}
