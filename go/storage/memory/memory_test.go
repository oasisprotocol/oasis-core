package memory

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestStorageMemory(t *testing.T) {
	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner()")

	backend := New(signer, false)
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend)
}
