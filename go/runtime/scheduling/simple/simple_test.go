package simple

import (
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/orderedmap"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/tests"
)

func TestSimpleScheduler(t *testing.T) {
	params := registry.TxnSchedulerParameters{
		Algorithm:         Name,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 16 * 1024 * 1024,
	}
	algo, err := New(orderedmap.Name, 100, params)
	require.NoError(t, err, "New()")

	tests.SchedulerImplementationTests(t, algo)
}

func BenchmarkSimpleSchedulerOrderedMap(b *testing.B) {
	params := registry.TxnSchedulerParameters{
		Algorithm:         Name,
		MaxBatchSize:      100,
		MaxBatchSizeBytes: 16 * 1024 * 1024,
	}
	algo, err := New(orderedmap.Name, 1000000, params)
	require.NoError(b, err, "New()")
	tests.SchedulerImplementationBenchmarks(b, algo)
}
