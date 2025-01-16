package bundle

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

type mockStore struct {
	manifestHashes map[hash.Hash]struct{}
}

func newMockStore() *mockStore {
	return &mockStore{
		manifestHashes: make(map[hash.Hash]struct{}),
	}
}

func (r *mockStore) HasManifest(hash hash.Hash) bool {
	_, ok := r.manifestHashes[hash]
	return ok
}

func (r *mockStore) AddManifest(manifest *Manifest, _ string) error {
	r.manifestHashes[manifest.Hash()] = struct{}{}
	return nil
}

func TestDiscovery(t *testing.T) {
	// Prepare a temporary directory for storing bundles.
	dir := t.TempDir()

	// Create bundle directory.
	path := ExplodedPath(dir)
	err := common.Mkdir(path)
	require.NoError(t, err)

	// Prepare runtime ID.
	var runtimeID common.Namespace
	err = runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)

	// Prepare version.
	version := version.Version{Major: 1}

	// Create discovery.
	store := newMockStore()
	discovery := NewDiscovery(dir, store)

	// Discovery should not find any bundles at this point.
	err = discovery.Discover()
	require.NoError(t, err)
	require.Equal(t, 0, len(store.manifestHashes))

	// Test multiple rounds of discovery.
	total := 0
	for r := 0; r < 3; r++ {
		// Add new bundle files for this round.
		for i := 0; i < r+2; i++ {
			version.Patch++

			bnd, err := createSyntheticBundle(runtimeID, version, []component.Kind{component.RONL})
			require.NoError(t, err)

			fn := filepath.Join(path, bnd.GenerateFilename())
			err = bnd.Write(fn)
			require.NoError(t, err)

			total++
		}

		// Discovery should find the newly added bundles.
		err = discovery.Discover()
		require.NoError(t, err)
		require.Equal(t, total, len(store.manifestHashes))
	}
}
