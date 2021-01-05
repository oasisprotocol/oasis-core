package api

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

func TestUpgradeMethod(t *testing.T) {
	require := require.New(t)

	// Test valid methods.
	for _, m := range []UpgradeMethod{
		UpgradeMethodInternal,
	} {
		enc, err := m.MarshalText()
		require.NoError(err, "MarshalText")

		var u UpgradeMethod
		err = u.UnmarshalText(enc)
		require.NoError(err, "UnmarshalText")
		require.Equal(m, u, "upgrade method should round-trip")

		require.EqualValues([]byte(u.String()), enc, "marshalled upgrade method should match")
	}

	// Test invalid method.
	u := UpgradeMethod(0)
	_, err := u.MarshalText()
	require.Error(err, "MarshalText on invalid upgrade method")
	require.Contains(u.String(), "unknown upgrade", "String() on invalid upgrade method")

	var m UpgradeMethod
	err = m.UnmarshalText([]byte{})
	require.Error(err, "unmarshal on invalid upgrade method")
}

func TestValidateBasic(t *testing.T) {
	hh, err := OwnHash()
	require.NoError(t, err, "OwnHash()")
	h := hex.EncodeToString(hh[:])

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
			msg: "invalid upgrade method should fail",
			d: &Descriptor{
				Method:     42,
				Epoch:      100,
				Identifier: h,
			},
			shouldErr: true,
		},
		{
			msg: "invalid epoch should fail",
			d: &Descriptor{
				Method:     UpgradeMethodInternal,
				Epoch:      0,
				Identifier: h,
			},
			shouldErr: true,
		},
		{
			msg: "invalid identifier should fail",
			d: &Descriptor{
				Method:     UpgradeMethodInternal,
				Epoch:      42,
				Identifier: "invalid",
			},
			shouldErr: true,
		},
		{
			msg: "valid internal descriptor should not fail",
			d: &Descriptor{
				Method:     UpgradeMethodInternal,
				Epoch:      42,
				Identifier: h,
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
	hh, err := OwnHash()
	require.NoError(t, err, "OwnHash()")
	h := hex.EncodeToString(hh[:])

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
			msg: "different name should not be equal",
			d1: &Descriptor{
				Name: "d1",
			},
			d2: &Descriptor{
				Name: "d2",
			},
			equals: false,
		},
		{
			msg: "different method should not be equal",
			d1: &Descriptor{
				Method: UpgradeMethodInternal,
			},
			d2:     &Descriptor{},
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
			msg: "different identifier should not be equal",
			d1: &Descriptor{
				Identifier: h,
			},
			d2:     &Descriptor{},
			equals: false,
		},
		{
			msg: "same descriptors should be equal",
			d1: &Descriptor{
				Name:       "d",
				Method:     UpgradeMethodInternal,
				Epoch:      42,
				Identifier: h,
			},
			d2: &Descriptor{
				Name:       "d",
				Method:     UpgradeMethodInternal,
				Epoch:      42,
				Identifier: h,
			},
			equals: true,
		},
	} {
		require.Equal(t, tc.equals, tc.d1.Equals(tc.d2), tc.msg)
	}
}

func TestEnsureCompatible(t *testing.T) {
	hh, err := OwnHash()
	require.NoError(t, err, "OwnHash()")
	h := hex.EncodeToString(hh[:])

	var emptyHash hash.Hash
	emptyH := hex.EncodeToString(emptyHash[:])

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
			msg: "different identifier should fail",
			d: &Descriptor{
				Method:     UpgradeMethodInternal,
				Epoch:      100,
				Identifier: emptyH,
			},
			shouldErr: true,
		},
		{
			msg: "matching identifier should not fail",
			d: &Descriptor{
				Method:     UpgradeMethodInternal,
				Epoch:      42,
				Identifier: h,
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
