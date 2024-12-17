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
	discovery := NewDiscovery(dataDir, registry)

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
