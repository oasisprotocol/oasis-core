package bundle

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

const testManifestEmptyJSON = "{}"

const testManifestFullJSON = `
{
  "name": "name",
  "id": "0000000000000000000000000000000000000000000000000000000000000000",
  "version": {},
  "components": [
    {
      "kind": "ronl",
      "name": "name",
      "version": {
        "major": 1,
        "minor": 2,
        "patch": 3
      },
      "elf": {
        "executable": "exe"
      },
      "sgx": {
        "executable": "exe",
        "signature": "sig"
      },
      "tdx": {
        "firmware": "firmware",
        "kernel": "kernel",
        "initrd": "initrd",
        "extra_kernel_options": ["opt1", "opt2"],
        "stage2_image": "image",
        "resources": {
          "memory": 1,
          "cpus": 2
        }
      },
      "identity": [
        {
          "hypervisor": "hypervisor",
          "enclave": "AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        }
      ],
      "disabled": true
    }
  ],
  "digests": {
    "a": "0100000000000000000000000000000000000000000000000000000000000000",
    "b": "0200000000000000000000000000000000000000000000000000000000000000"
  }
}
`

const testManifestLegacyJSON = `
{
  "name": "name",
  "id": "0000000000000000000000000000000000000000000000000000000000000000",
  "version": {
    "major": 1,
    "minor": 2,
    "patch": 3
  },
  "executable": "exe",
  "sgx": {
    "executable": "exe",
    "signature": "sig"
  },
  "components": [
    {
      "kind": "ronl",
      "name": "ronl",
      "executable": "exe",
      "sgx": {
        "executable": "exe",
        "signature": "sig"
      },
      "tdx": {
        "firmware": "firmware",
        "kernel": "kernel",
        "initrd": "initrd",
        "extra_kernel_options": ["opt1", "opt2"],
        "stage2_image": "image",
        "resources": {
          "memory": 1,
          "cpus": 2
        }
      },
      "disabled": true
    }
  ],
  "digests": {
    "a": "0100000000000000000000000000000000000000000000000000000000000000",
    "b": "0200000000000000000000000000000000000000000000000000000000000000"
  }
}
`

const testManifestLegacyVersionJSON = `
{
  "name": "name",
  "id": "0000000000000000000000000000000000000000000000000000000000000000",
  "version": {
    "major": 1,
    "minor": 2,
    "patch": 3
  },
  "components": [
    {
      "kind": "ronl"
    }
  ]
}
`

const testManifestMiniJSON = `
{
  "name": "name",
  "id": "0000000000000000000000000000000000000000000000000000000000000000",
  "version": {},
  "components": [
    {
      "kind": "ronl",
      "name": "name",
      "version": {},
      "tdx": {
        "firmware": "firmware",
        "kernel": "kernel",
        "extra_kernel_options": ["opt1", "opt2"],
        "stage2_image": "image",
        "resources": {
          "memory": 1,
          "cpus": 2
        }
      },
      "identity": [
        {
          "hypervisor": "hypervisor",
          "enclave": "AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADBAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        }
      ]
    }
  ],
  "digests": {
    "a": "0100000000000000000000000000000000000000000000000000000000000000",
    "b": "0200000000000000000000000000000000000000000000000000000000000000"
  }
}
`

func TestManifestHash_EmptyJSON(t *testing.T) {
	var manifest Manifest
	err := json.Unmarshal([]byte(testManifestEmptyJSON), &manifest)
	require.NoError(t, err)
	require.Equal(t, "dcc4f7c821d750caf4656cdee9f0bed52bee7697a00bab0aefb836149252cb1f", manifest.Hash().String())
}

func TestManifestHash_FullJSON(t *testing.T) {
	var manifest Manifest
	err := json.Unmarshal([]byte(testManifestFullJSON), &manifest)
	require.NoError(t, err)
	require.Equal(t, "2ddf81b85d08dbecb24571ba75858ec94871800b674d581cf37214c0d56263c3", manifest.Hash().String())
}

func TestManifestHash_MiniJSON(t *testing.T) {
	var manifest Manifest
	err := json.Unmarshal([]byte(testManifestMiniJSON), &manifest)
	require.NoError(t, err)
	require.Equal(t, "07c7b90d8412bf8efa6e96132888ac64dad330b0c1b538458fd05ee7a908617b", manifest.Hash().String())
}

func TestManifestHash_LegacyJSON(t *testing.T) {
	var manifest Manifest
	err := json.Unmarshal([]byte(testManifestLegacyJSON), &manifest)
	require.NoError(t, err)
	require.Equal(t, "bd2987c59d2c672dee5c723b2d01adf6a7030c67efa368c342b54f887c1fe188", manifest.Hash().String())
}

func TestManifestHash_LegacyVersionJSON(t *testing.T) {
	var manifest Manifest
	err := json.Unmarshal([]byte(testManifestLegacyVersionJSON), &manifest)
	require.NoError(t, err)

	// Verify that the manifest version is correctly copied to the RONL component.
	ronl, ok := manifest.GetComponentByID(component.ID_RONL)
	require.True(t, ok)
	require.Equal(t, manifest.Version, ronl.Version)

	// Ensure that the manifest hash remains unchanged even if the version is copied.
	newHash := manifest.Hash()
	ronl.Version = version.Version{}
	legacyHash := manifest.Hash()
	require.Equal(t, legacyHash, newHash)
}

func TestManifestHash_EmptyManifest(t *testing.T) {
	var manifest Manifest
	require.Equal(t, "dcc4f7c821d750caf4656cdee9f0bed52bee7697a00bab0aefb836149252cb1f", manifest.Hash().String())
}

func TestManifestHash_FullManifest(t *testing.T) {
	manifest := Manifest{
		Name: "name",
		ID:   common.Namespace{},
		Components: []*Component{
			{
				Kind:    component.RONL,
				Name:    "name",
				Version: version.Version{Major: 1, Minor: 2, Patch: 3}, // New field.
				ELF: &ELFMetadata{ // New field.
					Executable: "exe",
				},
				SGX: &SGXMetadata{
					Executable: "exe",
					Signature:  "sig",
				},
				TDX: &TDXMetadata{
					Firmware:           "firmware",
					Kernel:             "kernel",
					InitRD:             "initrd",
					ExtraKernelOptions: []string{"opt1", "opt2"},
					Stage2Image:        "image",
					Resources: TDXResources{
						Memory:   1,
						CPUCount: 2,
					},
				},
				Identities: []Identity{ // New field.
					{
						Hypervisor: "hypervisor",
						Enclave: sgx.EnclaveIdentity{
							MrEnclave: sgx.MrEnclave{1, 2, 3},
							MrSigner:  sgx.MrSigner{3, 4, 5},
						},
					},
				},
				Disabled: true,
			},
		},
		Digests: map[string]hash.Hash{
			"a": {1},
			"b": {2},
		},
	}
	require.Equal(t, "2ddf81b85d08dbecb24571ba75858ec94871800b674d581cf37214c0d56263c3", manifest.Hash().String())
}

func TestManifestHash_LegacyManifest(t *testing.T) {
	manifest := Manifest{
		Name:       "name",
		ID:         common.Namespace{},
		Version:    version.Version{Major: 1, Minor: 2, Patch: 3}, // Deprecated.
		Executable: "exe",                                         // Deprecated.
		SGX: &SGXMetadata{ // Deprecated
			Executable: "exe",
			Signature:  "sig",
		},
		Components: []*Component{
			{
				Kind:       component.RONL,
				Name:       "ronl",
				Executable: "exe", // Deprecated.
				SGX: &SGXMetadata{
					Executable: "exe",
					Signature:  "sig",
				},
				TDX: &TDXMetadata{
					Firmware:           "firmware",
					Kernel:             "kernel",
					InitRD:             "initrd",
					ExtraKernelOptions: []string{"opt1", "opt2"},
					Stage2Image:        "image",
					Resources: TDXResources{
						Memory:   1,
						CPUCount: 2,
					},
				},
				Disabled: true,
			},
		},
		Digests: map[string]hash.Hash{
			"a": {1},
			"b": {2},
		},
	}
	require.Equal(t, "bd2987c59d2c672dee5c723b2d01adf6a7030c67efa368c342b54f887c1fe188", manifest.Hash().String())
}
