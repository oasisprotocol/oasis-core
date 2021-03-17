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

func TestConvertGoModulesVersion(t *testing.T) {
	require := require.New(t)

	for _, tc := range []struct {
		goModVersion    string
		expectedVersion string
		valid           bool
	}{
		{"v0.2000.0", "20.0", true},
		{"v0.2000.1", "20.0.1", true},
		{"v0.2000.2", "20.0.2", true},
		{"v0.2000.3", "20.0.3", true},
		{"v0.2001.0", "20.1", true},
		{"v0.2001.0", "20.1", true},
		{"v0.2001.1", "20.1.1", true},
		{"v0.2001.2", "20.1.2", true},
		{"v0.2010.0", "20.10", true},
		{"v0.2010.1", "20.10.1", true},
		{"v0.2010.2", "20.10.2", true},
		{"v0.2100.0", "21.0", true},
		{"v0.2100.1", "21.0.1", true},
		{"v0.2101.0", "21.1", true},
		{"v0.2101.1", "21.1.1", true},
		{"v0.2101.10", "21.1.10", true},
		{"v0.2101.100", "21.1.100", true},
		{"v0.2199.0", "21.99", true},
		{"v0.2199.100", "21.99.100", true},
		{"v0.21100.0", "", false},
		{"0.2100.0", "", false},
		{"0.210.0", "", false},
		{"0.21.0", "", false},
		{"21.0", "", false},
		{"21.0.0", "", false},
	} {
		version := ConvertGoModulesVersion(tc.goModVersion)
		if tc.valid {
			require.Equal(tc.expectedVersion, version, "Valid Go modules version doesn't match")
		} else {
			require.Equal(VersionUndefined, version, "Invalid Go modules version is not undefined")
		}
	}
}

func TestProtocolVersionCompatible(t *testing.T) {
	for _, v := range []struct {
		versions     func() ProtocolVersions
		isCompatible bool
		msg          string
	}{
		{
			func() ProtocolVersions {
				v := Versions
				v.ConsensusProtocol.Patch++
				return v
			},
			true,
			"patch version change is compatible",
		},
		{
			func() ProtocolVersions {
				v := Versions
				v.ConsensusProtocol.Minor++
				return v
			},
			true,
			"minor version change is compatible",
		},
		{
			func() ProtocolVersions {
				v := Versions
				v.ConsensusProtocol.Major++
				return v
			},
			false,
			"consensus protocol major version change is not compatible",
		},
		{
			func() ProtocolVersions {
				v := Versions
				v.RuntimeCommitteeProtocol.Major++
				return v
			},
			false,
			"runtime committee protocol major version change is not compatible",
		},
		{
			func() ProtocolVersions {
				v := Versions
				v.RuntimeHostProtocol.Major++
				return v
			},
			false,
			"runtime host protocol major version change is not compatible",
		},
	} {
		require.Equal(t, v.isCompatible, Versions.Compatible(v.versions()), v.msg)
	}
}
