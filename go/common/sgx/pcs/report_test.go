package pcs

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
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

func TestComputeTdEnclaveIdentity(t *testing.T) {
	// Expected MRENCLAVE values are derived using SP 800-185 TupleHash256 with
	// TdEnclaveIdentityContext and the five 48-byte measurements from each report.
	for _, tc := range []struct {
		quote     string
		mrEnclave string
	}{
		{
			quote:     "quote_v4_tdx_ecdsa_p256.bin",
			mrEnclave: "63d522d975f7de879a8f3368b4f32dd1e8db635f5a24b651ce8ff81705028813",
		},
		{
			quote:     "quote_v4_tdx_ecdsa_p256_out_of_date.bin",
			mrEnclave: "9495c99b59584809ca2751f457df3c59217ad69e8081a5e8c64baa70214827fe",
		},
	} {
		t.Run(tc.quote, func(t *testing.T) {
			require := require.New(t)

			rawQuote, err := os.ReadFile("testdata/" + tc.quote)
			require.NoError(err)
			var quote Quote
			require.NoError(quote.UnmarshalBinary(rawQuote))
			report, ok := quote.reportBody.(*TdReport)
			require.True(ok, "expected a TDX report")

			identity := ComputeTdEnclaveIdentity(
				report.mrTd[:],
				report.rtmr0[:],
				report.rtmr1[:],
				report.rtmr2[:],
				report.rtmr3[:],
			)
			require.Equal(tc.mrEnclave, identity.MrEnclave.String())
			require.Equal(sgx.MrSigner{}, identity.MrSigner)

			identity = report.AsEnclaveIdentity()
			require.Equal(tc.mrEnclave, identity.MrEnclave.String())
			require.Equal(sgx.MrSigner{}, identity.MrSigner)
		})
	}
}
