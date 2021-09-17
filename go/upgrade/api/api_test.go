package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

func TestValidateBasic(t *testing.T) {
	for _, tc := range []struct {
		msg       string
		d         *Descriptor
		shouldErr bool
	}{
		{
			msg:       "empty upgrade should fail",
			d:         &Descriptor{},
			shouldErr: true,
		},
		{
			msg: "descriptor version below min should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(MinDescriptorVersion - 1),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     42,
			},
			shouldErr: true,
		},
		{
			msg: "descriptor version above max should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(MaxDescriptorVersion + 1),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     42,
			},
			shouldErr: true,
		},
		{
			msg: "epoch below min epoch should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     0,
			},
			shouldErr: true,
		},
		{
			msg: "epoch above max epoch should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     MaxUpgradeEpoch + 1,
			},
			shouldErr: true,
		},
		{
			msg: "too short handler should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TH",
				Target:    version.Versions,
				Epoch:     42,
			},
			shouldErr: true,
		},
		{
			msg: "too long handler should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "Tooooooo-Long-33-Char-TestHandler",
				Target:    version.Versions,
				Epoch:     42,
			},
			shouldErr: true,
		},
		{
			msg: "empty target version should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target:    version.ProtocolVersions{},
				Epoch:     42,
			},
			shouldErr: true,
		},
		{
			msg: "only consensus version in target version should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target: version.ProtocolVersions{
					ConsensusProtocol: version.Version{Major: 1, Minor: 2, Patch: 3},
				},
				Epoch: 42,
			},
			shouldErr: true,
		},
		{
			msg: "empty runtime host protocol target subversion should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target: version.ProtocolVersions{
					ConsensusProtocol: version.Version{
						Major: 0,
						Minor: 12,
						Patch: 1,
					},
					RuntimeCommitteeProtocol: version.Version{
						Major: 42,
						Minor: 0,
						Patch: 1,
					},
				},
				Epoch: 42,
			},
			shouldErr: true,
		},
		{
			msg: "valid descriptor should not fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     42,
			},
			shouldErr: false,
		},
	} {
		err := tc.d.ValidateBasic()
		if tc.shouldErr {
			require.NotNil(t, err, tc.msg)
			continue
		}
		require.Nil(t, err, tc.msg)
	}
}

func TestEquals(t *testing.T) {
	for _, tc := range []struct {
		msg    string
		d1     *Descriptor
		d2     *Descriptor
		equals bool
	}{
		{
			msg:    "empty upgrade descriptor should be equal",
			d1:     &Descriptor{},
			d2:     &Descriptor{},
			equals: true,
		},
		{
			msg: "different handler should not be equal",
			d1: &Descriptor{
				Handler: "d1",
			},
			d2: &Descriptor{
				Handler: "d2",
			},
			equals: false,
		},
		{
			msg: "different epoch should not be equal",
			d1: &Descriptor{
				Epoch: 42,
			},
			d2: &Descriptor{
				Epoch: 41,
			},
			equals: false,
		},
		{
			msg: "different target should not be equal",
			d1: &Descriptor{
				Target: version.Versions,
			},
			d2:     &Descriptor{},
			equals: false,
		},
		{
			msg: "different descriptor version should not be equal",
			d1: &Descriptor{
				Versioned: cbor.NewVersioned(123),
			},
			d2: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
			},
			equals: false,
		},
		{
			msg: "same descriptors should be equal",
			d1: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "d",
				Target:    version.Versions,
				Epoch:     42,
			},
			d2: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "d",
				Target:    version.Versions,
				Epoch:     42,
			},
			equals: true,
		},
	} {
		require.Equal(t, tc.equals, tc.d1.Equals(tc.d2), tc.msg)
	}
}

func TestEnsureCompatible(t *testing.T) {
	for _, tc := range []struct {
		msg       string
		d         *Descriptor
		shouldErr bool
	}{
		{
			msg:       "empty descriptor should fail",
			d:         &Descriptor{},
			shouldErr: true,
		},
		{
			msg: "different target should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Target:    version.ProtocolVersions{ConsensusProtocol: version.FromU64(42)},
				Epoch:     100,
			},
			shouldErr: true,
		},
		{
			msg: "different runtime target should not fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Target:    version.ProtocolVersions{ConsensusProtocol: version.ConsensusProtocol, RuntimeHostProtocol: version.FromU64(42)},
				Epoch:     100,
			},
			shouldErr: false,
		},
		{
			msg: "matching identifier should not fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Target:    version.Versions,
				Epoch:     42,
			},
			shouldErr: false,
		},
	} {
		err := tc.d.EnsureCompatible()
		if tc.shouldErr {
			require.NotNil(t, err, tc.msg)
			continue
		}
		require.Nil(t, err, tc.msg)
	}
}
