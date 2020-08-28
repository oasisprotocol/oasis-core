package simple

import (
	"testing"

	"github.com/stretchr/testify/require"

	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/tests"
)

func TestSimpleScheduler(t *testing.T) {
	params := registry.TxnSchedulerParameters{
		Algorithm:         Name,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 16 * 1024 * 1024,
	}
	algo, err := New(100, params)
	require.NoError(t, err, "New()")

	tests.SchedulerImplementationTests(t, algo)
}
