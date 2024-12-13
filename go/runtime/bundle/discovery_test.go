package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

var _ Registry = (*mockRegistry)(nil)

type mockRegistry struct {
	manifestHashes map[hash.Hash]struct{}
}

// HasBundle implements Registry.
func (r *mockRegistry) HasBundle(manifestHash hash.Hash) bool {
	_, ok := r.manifestHashes[manifestHash]
	return ok
}

// AddBundle implements Registry.
func (r *mockRegistry) AddBundle(_ string, manifestHash hash.Hash) error {
	r.manifestHashes[manifestHash] = struct{}{}
	return nil
}

// GetVersions implements Registry.
func (r *mockRegistry) GetVersions(common.Namespace) []version.Version {
	panic("unimplemented")
}

// WatchVersions implements Registry.
func (r *mockRegistry) WatchVersions(common.Namespace) (<-chan version.Version, *pubsub.Subscription) {
	panic("unimplemented")
}

// GetManifests implements Registry.
func (r *mockRegistry) GetManifests() []*Manifest {
	panic("unimplemented")
}

// GetName implements Registry.
func (r *mockRegistry) GetName(common.Namespace, version.Version) (string, error) {
	panic("unimplemented")
}

// GetComponents implements Registry.
func (r *mockRegistry) GetComponents(common.Namespace, version.Version) ([]*ExplodedComponent, error) {
	panic("unimplemented")
}

func newMockListener() *mockRegistry {
	return &mockRegistry{
		manifestHashes: make(map[hash.Hash]struct{}),
	}
}

func TestBundleDiscovery(t *testing.T) {
	// Prepare a temporary directory for storing bundles.
	dataDir := t.TempDir()

	// Create discovery.
	registry := newMockListener()
	discovery := NewDiscovery(dataDir, registry, nil)

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
	require.Equal(t, 0, len(registry.manifestHashes))

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
		require.Equal(t, total, len(registry.manifestHashes))
	}
}

func TestCleanStaleExplodedBundles(t *testing.T) {
	// Prepare a temporary directory for storing bundles.
	dir := t.TempDir()

	// Create Runtime IDs.
	var runtimeID1 common.Namespace
	err := runtimeID1.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)

	var runtimeID2 common.Namespace
	err = runtimeID2.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000002")
	require.NoError(t, err)

	// Create discovery, that has only runtimeID2 registered.
	registry := newMockListener()
	discovery := NewDiscovery(dir, registry, []common.Namespace{runtimeID2})

	version1 := version.Version{Major: 1}
	version2 := version.Version{Major: 2}

	// Generate synthetic bundles.
	path0, err := createSyntheticBundle(dir, runtimeID1, version1, []component.Kind{component.RONL, component.ROFL})
	require.NoError(t, err)

	path1, err := createSyntheticBundle(dir, runtimeID1, version2, []component.Kind{component.ROFL})
	require.NoError(t, err)

	path2, err := createSyntheticBundle(dir, runtimeID2, version1, []component.Kind{component.RONL, component.ROFL})
	require.NoError(t, err)

	path3, err := createSyntheticBundle(dir, runtimeID2, version1, []component.Kind{component.ROFL})
	require.NoError(t, err)

	paths := []string{path0, path1, path2, path3}

	for _, path := range paths {
		// Explode the bundle.
		bnd, err := Open(path)
		require.NoError(t, err)
		_, err = bnd.WriteExploded(dir)
		require.NoError(t, err)
	}

	// Ensure bundle were exploded successfully.
	entries, err := os.ReadDir(ExplodedPath(dir))
	require.NoError(t, err)
	// 2 x RONL manifest + "detached subdir".
	require.Equal(t, 3, len(entries))
	entries, err = os.ReadDir(DetachedExplodedPath(dir))
	require.NoError(t, err)
	// 2 s ROFL manifests.
	require.Equal(t, 2, len(entries))

	// Clean stale bundles.
	discovery.cleanBundles()

	// All exploded bundles for runtimeID1 should be removed.
	entries, err = os.ReadDir(ExplodedPath(dir))
	require.NoError(t, err)
	// 1 x RONL manifest + "detached subdir".
	require.Equal(t, 2, len(entries))
	entries, err = os.ReadDir(DetachedExplodedPath(dir))
	require.NoError(t, err)
	// 1 X ROFL manifest.
	require.Equal(t, 1, len(entries))
}
