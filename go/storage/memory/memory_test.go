package memory

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestStorageMemory(t *testing.T) {
	pk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey()")

	backend := New(&pk)
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend)
}
