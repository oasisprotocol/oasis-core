package simple

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/priorityqueue"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/tests"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

func TestSimpleSchedulerPriorityQueue(t *testing.T) {
	weightLimits := map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 16 * 1024 * 1024,
	}

	algo, err := New(priorityqueue.Name, 100, Name, weightLimits)
	require.NoError(t, err, "New()")
	tests.SchedulerImplementationTests(t, algo)
}

func BenchmarkSimpleSchedulerPriorityQueue(b *testing.B) {
	weightLimits := map[transaction.Weight]uint64{
		transaction.WeightCount:     1000,
		transaction.WeightSizeBytes: 16 * 1024 * 1024,
	}

	algo, err := New(priorityqueue.Name, 1000000, Name, weightLimits)
	require.NoError(b, err, "New()")
	tests.SchedulerImplementationBenchmarks(b, algo)
}
