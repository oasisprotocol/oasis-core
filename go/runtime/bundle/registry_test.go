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
				Name:    "my-rofl-comp",
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

	var runtimeID3 common.Namespace
	err = runtimeID3.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000003")
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
		err = registry.AddManifest(&ExplodedManifest{Manifest: bnds[i].Manifest})
		require.NoError(t, err)
	}

	// Attempt to add the first manifest again (duplicate hash).
	err = registry.AddManifest(&ExplodedManifest{Manifest: bnds[0].Manifest})
	require.NoError(t, err)

	// Attempt to add the fourth manifest (duplicate RONL component).
	err = registry.AddManifest(&ExplodedManifest{Manifest: bnds[3].Manifest})
	require.Error(t, err)
	require.ErrorContains(t, err, "duplicate component 'ronl', version '1.0.0', for runtime '8000000000000000000000000000000000000000000000000000000000000001'")

	// Fetch manifests.
	manifests := registry.Manifests()
	require.Equal(t, 3, len(manifests))

	// Fetch components for runtime 1.
	comps := registry.Components(runtimeID1)
	require.Equal(t, 3, len(comps))
	require.Equal(t, version1, comps[0].Version)
	require.Equal(t, version2, comps[1].Version)
	require.Equal(t, version1, comps[2].Version)
	require.Equal(t, component.ROFL, comps[0].Kind)
	require.Equal(t, component.ROFL, comps[1].Kind)
	require.Equal(t, component.RONL, comps[2].Kind)

	// Fetch components for runtime 2.
	comps = registry.Components(runtimeID2)
	require.Equal(t, 1, len(comps))
	require.Equal(t, version3, comps[0].Version)
	require.Equal(t, component.RONL, comps[0].Kind)

	// Fetch components for runtime 3 (no components).
	comps = registry.Components(runtimeID3)
	require.Empty(t, comps)
}
