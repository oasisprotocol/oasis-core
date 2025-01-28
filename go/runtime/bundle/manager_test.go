package bundle

import (
	"testing"

	"github.com/stretchr/testify/require"

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

func (r *mockStore) HasManifest(hash hash.Hash) bool {
	_, ok := r.manifestHashes[hash]
	return ok
}

func (r *mockStore) AddManifest(manifest *ExplodedManifest) error {
	r.manifestHashes[manifest.Hash()] = struct{}{}
	return nil
}

func TestRegisterManifest(t *testing.T) {
	store := newMockStore()
	manager, err := NewManager("", nil, store)
	require.NoError(t, err)

	manifests := []*ExplodedManifest{
		{
			Manifest:        &Manifest{Name: "manifest1"},
			ExplodedDataDir: "dir1",
		},
		{
			Manifest:        &Manifest{Name: "manifest2"},
			ExplodedDataDir: "dir2",
		},
	}

	err = manager.registerManifests(manifests)
	require.NoError(t, err)
	require.Equal(t, len(manifests), len(store.manifestHashes))
}
