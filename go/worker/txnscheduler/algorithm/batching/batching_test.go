package batching

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/worker/txnscheduler/algorithm/tests"
)

func TestBatchingAlgo(t *testing.T) {
	viper.Set(cfgMaxQueueSize, 100)
	viper.Set(cfgMaxBatchSize, 10)
	viper.Set(cfgMaxBatchSizeBytes, "16mb")

	algo, err := New()
	require.NoError(t, err, "New()")

	tests.AlgorithmImplementationTests(t, algo)
}
