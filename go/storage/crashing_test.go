package storage

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage/memory"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestCrashingBackendDoNotInterfere(t *testing.T) {
	timeSource := mock.New()
	pk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey()")

	memoryBackend := memory.New(timeSource, &pk)
	backend := newCrashingWrapper(memoryBackend)

	crash.Config(map[string]float64{
		"storage.write.before": 0.0,
		"storage.write.after":  0.0,
		"storage.read.before":  0.0,
		"storage.read.after":   0.0,
	})

	tests.StorageImplementationTests(t, backend, timeSource, true)
}
