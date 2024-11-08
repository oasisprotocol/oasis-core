package bundle

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
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
		Components: []*Component{
			{
				Kind:       component.RONL,
				Executable: "runtime.bin",
				SGX: &SGXMetadata{
					Executable: "runtime.sgx",
				},
				Identities: []Identity{
					{
						Hypervisor: "test",
						Enclave: sgx.EnclaveIdentity{
							MrSigner:  sgx.MrSigner{0x01},
							MrEnclave: sgx.MrEnclave{0x02},
						},
					},
				},
			},
		},
	}
	bundle := &Bundle{
		Manifest: manifest,
	}

	require.False(t, manifest.IsDetached(), "manifest with RONL component should not be detached")

	t.Run("Add_Write", func(t *testing.T) {
		// Generate random assets.
		randomBuffer := func() []byte {
			b := make([]byte, 1024*256)
			_, err := rand.Read(b)
			require.NoError(t, err, "rand.Read")
			return b
		}

		err := bundle.Add(manifest.Components[0].Executable, NewBytesData(execBuf))
		require.NoError(t, err, "bundle.Add(elf)")
		err = bundle.Add(manifest.Components[0].SGX.Executable, NewBytesData(randomBuffer()))
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

		ensureBundlesEqual(t, bundle, bundle2, "opened bundle mismatch")

		// Test enclave identity is correct.
		eids, err := bundle2.EnclaveIdentities(component.ID_RONL)
		require.NoError(t, err, "EnclaveIdentities")
		require.Len(t, eids, 1)
		require.Equal(t, "0100000000000000000000000000000000000000000000000000000000000000", eids[0].MrSigner.String())
		require.Equal(t, "0200000000000000000000000000000000000000000000000000000000000000", eids[0].MrEnclave.String())
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
		_, err := bundle.WriteExploded(tmpDir)
		require.NoError(t, err, "WriteExploded")

		// Abuse the fact that we do an integrity check if the bundle
		// is already exploded.
		_, err = bundle.WriteExploded(tmpDir)
		require.NoError(t, err, "WriteExploded(again)")
	})
}

func TestDeatchedBundle(t *testing.T) {
	execFile := os.Args[0]
	execBuf, err := os.ReadFile(execFile)
	if err != nil {
		t.Fatalf("failed to read test executable %s: %v", execFile, err)
	}

	// Create a synthetic bundle.
	//
	// Assets will be populated during the Add/Write combined test.
	tmpDir := t.TempDir()
	bundleFn := filepath.Join(tmpDir, "detached-bundle.orc")
	manifest := &Manifest{
		Name: "test-runtime",
		ID: func() common.Namespace {
			var id common.Namespace
			if err := id.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff"); err != nil {
				panic("failed to unmarshal id")
			}
			return id
		}(),
		Components: []*Component{
			// No RONL component in the manifest.
			{
				Kind:       component.ROFL,
				Executable: "runtime.bin",
				SGX: &SGXMetadata{
					Executable: "runtime.sgx",
				},
			},
		},
	}
	bundle := &Bundle{
		Manifest: manifest,
	}

	require.True(t, manifest.IsDetached(), "manifest without RONL component should be detached")

	t.Run("Add_Write", func(t *testing.T) {
		// Generate random assets.
		randomBuffer := func() []byte {
			b := make([]byte, 1024*256)
			_, err := rand.Read(b)
			require.NoError(t, err, "rand.Read")
			return b
		}

		err := bundle.Add(manifest.Components[0].Executable, NewBytesData(execBuf))
		require.NoError(t, err, "bundle.Add(elf)")
		err = bundle.Add(manifest.Components[0].SGX.Executable, NewBytesData(randomBuffer()))
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

		ensureBundlesEqual(t, bundle, bundle2, "opened bundle mismatch")
	})

	t.Run("Explode", func(t *testing.T) {
		_, err := bundle.WriteExploded(tmpDir)
		require.NoError(t, err, "WriteExploded")

		// Abuse the fact that we do an integrity check if the bundle
		// is already exploded.
		_, err = bundle.WriteExploded(tmpDir)
		require.NoError(t, err, "WriteExploded(again)")
	})
}

func TestBytesData(t *testing.T) {
	require := require.New(t)

	data := []byte("this is a test")
	bd := NewBytesData(data)
	rdData, err := ReadAllData(bd)
	require.NoError(err)
	require.EqualValues(data, rdData)

	hData, err := HashAllData(bd)
	require.NoError(err)
	require.EqualValues("6c53016ac6f75b6a86dbd56070cbed58a5880071fa3ae44f1211ec72958ae941", hData.Hex())
}

func TestFileData(t *testing.T) {
	require := require.New(t)

	tmpDir := t.TempDir()
	fn := filepath.Join(tmpDir, "test.bin")

	data := []byte("this is a test")
	err := os.WriteFile(fn, data, 0o600)
	require.NoError(err)

	fd := NewFileData(fn)
	rdData, err := ReadAllData(fd)
	require.NoError(err)
	require.EqualValues(data, rdData)

	hData, err := HashAllData(fd)
	require.NoError(err)
	require.EqualValues("6c53016ac6f75b6a86dbd56070cbed58a5880071fa3ae44f1211ec72958ae941", hData.Hex())
}

func ensureBundlesEqual(t *testing.T, b1, b2 *Bundle, msg string) {
	require.EqualValues(t, len(b1.Data), len(b2.Data), msg)
	for fn := range b1.Data {
		require.Contains(t, b2.Data, fn, msg)

		d1, err := ReadAllData(b1.Data[fn])
		require.NoError(t, err, "b1.ReadAllData")
		d2, err := ReadAllData(b2.Data[fn])
		require.NoError(t, err, "b2.ReadAllData")

		require.EqualValues(t, d1, d2, msg)
	}
}
