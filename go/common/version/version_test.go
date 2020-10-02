package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaskNonMajor(t *testing.T) {
	require := require.New(t)

	v1 := Version{1, 1, 0}
	v2 := Version{1, 1, 5}
	v3 := Version{1, 4, 10}
	require.Equal(v1.MaskNonMajor(), v2.MaskNonMajor(), "version.MaskNonMajor() should match")
	require.Equal(v2.MaskNonMajor(), v3.MaskNonMajor(), "version.MaskNonMajor() should match")
	v4 := Version{2, 1, 0}
	require.NotEqual(v1.MaskNonMajor(), v4.MaskNonMajor(), "version.MaskNonMajor() should not match")
}

func TestMajorMinor(t *testing.T) {
	require := require.New(t)

	v1 := Version{1, 1, 0}
	v2 := Version{1, 1, 5}
	v3 := Version{1, 1, 10}
	require.Equal(v1.MajorMinor(), v2.MajorMinor(), "version.MajorMinor() should match")
	require.Equal(v2.MajorMinor(), v3.MajorMinor(), "version.MajorMinor() should match")
	v4 := Version{1, 2, 0}
	require.NotEqual(v1.MajorMinor(), v4.MajorMinor(), "version.MajorMinor() should not match")
}

func TestParseSemVer(t *testing.T) {
	require := require.New(t)

	for _, v := range []struct {
		semver   string
		expected Version
	}{
		{"1.0.0", Version{1, 0, 0}},
		{"2.1.3", Version{2, 1, 3}},
		{"1.0.0-alpha", Version{1, 0, 0}},
		{"1.0.0-alpha+1.2", Version{1, 0, 0}},
		{"1.8.2-beta.1.13", Version{1, 8, 2}},
	} {
		require.Equal(parseSemVerStr(v.semver), v.expected, "parseSemVerStr()")
	}
}

func TestFromToU64(t *testing.T) {
	require := require.New(t)

	for _, v := range []Version{
		{},
		{0, 0, 0},
		{1, 1, 1},
		{10, 20, 30},
	} {
		require.Equal(FromU64(v.ToU64()), v, "FromU64(version.ToU64())")
	}
}
