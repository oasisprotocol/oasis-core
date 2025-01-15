package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

type mockStore struct {
	manifestHashes map[hash.Hash]struct{}
}

func newMockStore() *mockStore {
	return &mockStore{
		manifestHashes: make(map[hash.Hash]struct{}),
	}
}

func (r *mockStore) HasBundle(manifestHash hash.Hash) bool {
	_, ok := r.manifestHashes[manifestHash]
	return ok
}

func (r *mockStore) AddBundle(manifestHash hash.Hash, _ string) error {
	r.manifestHashes[manifestHash] = struct{}{}
	return nil
}

func TestBundleDiscovery(t *testing.T) {
	// Prepare a temporary directory for storing bundles.
	dataDir := t.TempDir()

	// Create discovery.
	store := newMockStore()
	discovery := NewDiscovery(dataDir, store)

	// Get bundle directory.
	dir := ExplodedPath(dataDir)
	err := common.Mkdir(dir)
	require.NoError(t, err)

	// Create an empty file, which should be ignored by the discovery.
	file, err := os.Create(filepath.Join(dir, fmt.Sprintf("bundle%s", FileExtension)))
	require.NoError(t, err)
	file.Close()

	// Discovery should not find any bundles at this point.
	err = discovery.Discover()
	require.NoError(t, err)
	require.Equal(t, 0, len(store.manifestHashes))

	// Test multiple rounds of discovery.
	total := 0
	for r := 0; r < 3; r++ {
		// Add new bundle files for this round.
		for i := 0; i < r+2; i++ {
			manifestHash := hash.Hash{byte(total)}
			fn := fmt.Sprintf("%s%s", manifestHash.Hex(), FileExtension)
			path := filepath.Join(dir, fn)

			file, err := os.Create(path)
			require.NoError(t, err)

			err = file.Close()
			require.NoError(t, err)

			total++
		}

		// Discovery should find the newly added bundles.
		err = discovery.Discover()
		require.NoError(t, err)
		require.Equal(t, total, len(store.manifestHashes))
	}
}
