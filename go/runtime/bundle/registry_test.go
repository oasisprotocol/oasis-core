package bundle

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

func createSyntheticBundle(runtimeID common.Namespace, version version.Version, components []component.Kind) (*Bundle, error) {
	manifest := &Manifest{
		Name:       "test-runtime",
		ID:         runtimeID,
		Components: make([]*Component, 0),
	}

	for _, comp := range components {
		switch comp {
		case component.RONL:
			manifest.Components = append(manifest.Components, &Component{
				Kind:    component.RONL,
				Version: version,
				ELF: &ELFMetadata{
					Executable: "runtime.bin",
				},
			})
		case component.ROFL:
			manifest.Components = append(manifest.Components, &Component{
				Kind:    component.ROFL,
				Version: version,
			})
		default:
		}
	}

	bnd := Bundle{
		Manifest: manifest,
	}

	if slices.Contains(components, component.RONL) {
		if err := bnd.Add(manifest.Components[0].ELF.Executable, NewBytesData([]byte{1})); err != nil {
			return nil, err
		}
	}

	bnd.manifestHash = manifest.Hash()

	return &bnd, nil
}

func TestRegistry(t *testing.T) {
	// Prepare runtimes.
	var runtimeID1 common.Namespace
	err := runtimeID1.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)

	var runtimeID2 common.Namespace
	err = runtimeID2.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000002")
	require.NoError(t, err)

	// Prepare versions.
	version1 := version.Version{Major: 1}
	version2 := version.Version{Major: 2}
	version3 := version.Version{Major: 3}

	// Generate synthetic bundles.
	bnd0, err := createSyntheticBundle(runtimeID1, version1, []component.Kind{component.RONL, component.ROFL})
	require.NoError(t, err)

	bnd1, err := createSyntheticBundle(runtimeID1, version2, []component.Kind{component.ROFL})
	require.NoError(t, err)

	bnd2, err := createSyntheticBundle(runtimeID2, version3, []component.Kind{component.RONL})
	require.NoError(t, err)

	bnd3, err := createSyntheticBundle(runtimeID1, version1, []component.Kind{component.RONL})
	require.NoError(t, err)

	bnds := []*Bundle{bnd0, bnd1, bnd2, bnd3}

	// Create registry instance.
	registry := NewRegistry()

	// Add manifests to the registry.
	for i := 0; i < 3; i++ {
		err = registry.AddManifest(bnds[i].Manifest, "")
		require.NoError(t, err)
	}

	// Attempt to add the first manifest again (duplicate hash).
	err = registry.AddManifest(bnds[0].Manifest, "")
	require.NoError(t, err)

	// Attempt to add the fourth manifest (duplicate RONL component).
	err = registry.AddManifest(bnds[3].Manifest, "")
	require.Error(t, err)
	require.ErrorContains(t, err, "duplicate component 'ronl', version '1.0.0', for runtime '8000000000000000000000000000000000000000000000000000000000000001'")

	// Fetch manifests.
	manifests := registry.GetManifests()
	require.Equal(t, 2, len(manifests))

	// Fetch components for runtime 1, version 1.
	comps, err := registry.GetComponents(runtimeID1, version1)
	require.NoError(t, err)
	require.Equal(t, 2, len(comps))
	require.Equal(t, version1, comps[0].Version)
	require.Equal(t, version2, comps[1].Version)

	// Fetch components for runtime 2, version 3.
	comps, err = registry.GetComponents(runtimeID2, version3)
	require.NoError(t, err)
	require.Equal(t, 1, len(comps))
	require.Equal(t, version3, comps[0].Version)

	// Attempt to fetch components for runtime 1, version 2 (no RONL component).
	_, err = registry.GetComponents(runtimeID1, version2)
	require.Error(t, err)
	require.ErrorContains(t, err, "component 'ronl', version '2.0.0', for runtime '8000000000000000000000000000000000000000000000000000000000000001' not found")

	// Attempt to fetch components for runtime 1, version 3 (no components).
	_, err = registry.GetComponents(runtimeID1, version3)
	require.Error(t, err)
	require.ErrorContains(t, err, "component 'ronl', version '3.0.0', for runtime '8000000000000000000000000000000000000000000000000000000000000001' not found")
}
