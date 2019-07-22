package memory

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

var testNs common.Namespace

func TestStorageMemory(t *testing.T) {
	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner()")

	backend := New(signer, false)
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend, testNs)
}

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("ekiden storage memory test ns"))
	copy(testNs[:], ns[:])
}
