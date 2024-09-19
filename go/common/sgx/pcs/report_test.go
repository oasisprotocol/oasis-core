package pcs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTdAttributes(t *testing.T) {
	require := require.New(t)

	attrs := TdAttributeDebug | TdAttributeSeptVeDisable | TdAttributePKS
	require.True(attrs.Contains(TdAttributeDebug))
	require.True(attrs.Contains(TdAttributeSeptVeDisable))
	require.True(attrs.Contains(TdAttributePKS))
	require.True(attrs.Contains(TdAttributeDebug | TdAttributeSeptVeDisable))
	require.False(attrs.Contains(TdAttributeKL))
	require.False(attrs.Contains(TdAttributeDebug | TdAttributeKL))

	var dec TdAttributes
	reserved := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	err := dec.UnmarshalBinary(reserved)
	require.Error(err, "UnmarshalBinary should fail for reserved attributes")

	reserved = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	err = dec.UnmarshalBinary(reserved)
	require.Error(err, "UnmarshalBinary should fail for reserved attributes")
}
