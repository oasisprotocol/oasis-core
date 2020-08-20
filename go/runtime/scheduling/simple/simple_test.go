package simple

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/tests"
)

func TestSimpleScheduler(t *testing.T) {
	algo, err := New(100, 10, 16*1024*1024)
	require.NoError(t, err, "New()")

	tests.SchedulerImplementationTests(t, algo)
}
