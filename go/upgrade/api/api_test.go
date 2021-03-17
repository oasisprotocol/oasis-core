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
			msg: "invalid epoch should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     0,
			},
			shouldErr: true,
		},
		{
			msg: "invalid target should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(LatestDescriptorVersion),
				Handler:   "TestHandler",
				Target:    version.ProtocolVersions{},
				Epoch:     42,
			},
			shouldErr: true,
		},
		{
			msg: "invalid descriptor version should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(maxDescriptorVersion + 1),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     42,
			},
			shouldErr: true,
		},
		{
			msg: "invalid descriptor version should fail",
			d: &Descriptor{
				Versioned: cbor.NewVersioned(minDescriptorVersion - 1),
				Handler:   "TestHandler",
				Target:    version.Versions,
				Epoch:     42,
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
				Target:    version.ProtocolVersions{RuntimeHostProtocol: version.FromU64(42)},
				Epoch:     100,
			},
			shouldErr: true,
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
