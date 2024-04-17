package pcs

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMockQuote(t *testing.T) {
	require := require.New(t)
	now := time.Unix(1671497404, 0)

	_, err := NewMockQuote(nil)
	require.Error(err)
	_, err = NewMockQuote([]byte("invalid"))
	require.Error(err)

	// Load quote from test vector so we can have a valid report.
	rawTestVector, err := os.ReadFile("testdata/quote_v3_ecdsa_p256_pck_chain.bin")
	require.NoError(err, "Read test vector")
	var testVector Quote
	err = testVector.UnmarshalBinary(rawTestVector)
	require.NoError(err, "Parse test vector")
	rawReport := testVector.ISVReport.raw

	// Generate mock quote for the given report.
	mockQuote, err := NewMockQuote(rawReport)
	require.NoError(err, "NewMockQuote")

	// Make sure we can unmarshal the mock quote.
	var quote Quote
	err = quote.UnmarshalBinary(mockQuote)
	require.NoError(err, "Parse generated mock quote")

	// Check what information we need to retrieve based on what is in the quote.
	qs, ok := quote.Signature.(*QuoteSignatureECDSA_P256)
	require.True(ok, "attestation key type should be correct")

	// Verify PCK certificate and extract the information required to get the TCB bundle.
	_, err = qs.VerifyPCK(now)
	require.NoError(err, "VerifyPCK should work on mock quote")

	// Prepare TCB bundle needed for verification.
	rawTCBInfo, err := os.ReadFile("testdata/tcb_info_v3_fmspc_00606A000000.json") // From PCS V4 response.
	require.NoError(err, "Read test vector")
	rawCerts, err := os.ReadFile("testdata/tcb_info_v3_fmspc_00606A000000_certs.pem") // From PCS V4 response (TCB-Info-Issuer-Chain header).
	require.NoError(err, "Read test vector")
	rawQEIdentity, err := os.ReadFile("testdata/qe_identity_v2.json") // From PCS V4 response.
	require.NoError(err, "Read test vector")

	var tcbInfo SignedTCBInfo
	err = json.Unmarshal(rawTCBInfo, &tcbInfo)
	require.NoError(err, "Parse TCB info")

	var qeIdentity SignedQEIdentity
	err = json.Unmarshal(rawQEIdentity, &qeIdentity)
	require.NoError(err, "Parse QE identity")

	tcbBundle := TCBBundle{
		TCBInfo:      tcbInfo,
		QEIdentity:   qeIdentity,
		Certificates: rawCerts,
	}

	_, err = quote.Verify(nil, now, &tcbBundle)
	require.Error(err, "Verify mock quote signature should fail")
}

func TestNewMockQuoteReportWithMAC(t *testing.T) {
	require := require.New(t)

	// Generate mock quote for the report with MAC.
	var rawReport [432]byte
	mockQuote, err := NewMockQuote(rawReport[:])
	require.NoError(err, "NewMockQuote")

	// Make sure we can unmarshal the mock quote.
	var quote Quote
	err = quote.UnmarshalBinary(mockQuote)
	require.NoError(err, "Parse generated mock quote")
}
