package queue

import (
	"testing"

	tests "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

func TestIncomingQueue(t *testing.T) {
	queue := New(api.Config{
		MaxPoolSize:       10,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 10,
	})
	tests.TxPoolImplementationTests(t, queue)
}

func BenchmarkIncomingQueue(b *testing.B) {
	queue := New(api.Config{
		MaxPoolSize:       10,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 10,
	})
	tests.TxPoolImplementationBenchmarks(b, queue)
}
