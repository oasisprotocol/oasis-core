package orderedmap

import (
	"testing"

	tests "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

func TestOrderedQueue(t *testing.T) {
	queue := New(api.Config{
		MaxPoolSize: 10,
	})
	tests.TxPoolImplementationTests(t, queue)
}

func BenchmarkOrderedQueue(b *testing.B) {
	queue := New(api.Config{
		MaxPoolSize: 10,
	})
	tests.TxPoolImplementationBenchmarks(b, queue)
}
