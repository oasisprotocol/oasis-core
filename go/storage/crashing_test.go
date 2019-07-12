package storage

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crash"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/storage/memory"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestCrashingBackendDoNotInterfere(t *testing.T) {
	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner()")

	memoryBackend := memory.New(signer, false)
	backend := newCrashingWrapper(memoryBackend)

	crash.Config(map[string]float64{
		"storage.write.before": 0.0,
		"storage.write.after":  0.0,
		"storage.read.before":  0.0,
		"storage.read.after":   0.0,
	})

	tests.StorageImplementationTests(t, backend)
}
