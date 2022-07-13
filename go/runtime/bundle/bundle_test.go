package bundle

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
)

func TestBundle(t *testing.T) {
	execFile := os.Args[0]
	execBuf, err := os.ReadFile(execFile)
	if err != nil {
		t.Fatalf("failed to read test executable %s: %v", execFile, err)
	}

	// Create a synthetic bundle.
	//
	// Assets will be populated during the Add/Write combined test.
	tmpDir := t.TempDir()
	bundleFn := filepath.Join(tmpDir, "bundle.orc")
	manifest := &Manifest{
		Name: "test-runtime",
		ID: func() common.Namespace {
			var id common.Namespace
			if err := id.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff"); err != nil {
				panic("failed to unmarshal id")
			}
			return id
		}(),
		Executable: "runtime.bin",
		SGX: &SGXMetadata{
			Executable: "runtime.sgx",
		},
	}
	bundle := &Bundle{
		Manifest: manifest,
	}

	t.Run("Add_Write", func(t *testing.T) {
		// Generate random assets.
		randomBuffer := func() []byte {
			b := make([]byte, 1024*256)
			_, err := rand.Read(b)
			require.NoError(t, err, "rand.Read")
			return b
		}

		err := bundle.Add(manifest.Executable, execBuf)
		require.NoError(t, err, "bundle.Add(elf)")
		err = bundle.Add(manifest.SGX.Executable, randomBuffer())
		require.NoError(t, err, "bundle.Add(sgx)")

		err = bundle.Write(bundleFn)
		require.NoError(t, err, "bundle.Write")
	})

	t.Run("Open", func(t *testing.T) {
		bundle2, err := Open(bundleFn)
		require.NoError(t, err, "Open")

		// Ignore the manifest, the bundle we used to create the file
		// will not have it.
		delete(bundle2.Manifest.Digests, manifestName)
		delete(bundle2.Data, manifestName)

		require.EqualValues(t, bundle, bundle2, "opened bundle mismatch")
	})

	t.Run("ResetManifest", func(t *testing.T) {
		bundle2, err := Open(bundleFn)
		require.NoError(t, err, "Open")

		err = bundle2.Write(bundleFn + ".copy")
		require.Error(t, err, "bundle.Write should fail with existing manifest")

		bundle2.ResetManifest()

		err = bundle2.Write(bundleFn + ".copy")
		require.NoError(t, err, "bundle.Write")
	})

	t.Run("Explode", func(t *testing.T) {
		err := bundle.WriteExploded(tmpDir)
		require.NoError(t, err, "WriteExploded")

		// Abuse the fact that we do an integrity check if the bundle
		// is already exploded.
		err = bundle.WriteExploded(tmpDir)
		require.NoError(t, err, "WriteExploded(again)")
	})
}
