package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
