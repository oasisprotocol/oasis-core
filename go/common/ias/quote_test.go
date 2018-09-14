package ias

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"encoding/hex"
)

func TestQuote(t *testing.T) {
	raw, sig, certs := loadAVRv2(t)
	avr, err := DecodeAVR(raw, sig, certs, time.Now())
	require.NoError(t, err, "DecodeAVR")

	rawQuote := avr.ISVEnclaveQuoteBody
	quote, err := DecodeQuote(rawQuote)
	require.NoError(t, err, "DecodeQuote")

	require.EqualValues(t, 2, quote.Body.Version, "VERSION")
	require.Equal(t, SignatureLinkable, quote.Body.SignatureType, "SIGNATURE_TYPE")
	require.EqualValues(t, 0x00000ae3, quote.Body.GID, "GID")
	require.EqualValues(t, 5, quote.Body.ISVSVNQuotingEnclave, "ISVSVN_QE")
	require.EqualValues(t, 4, quote.Body.ISVSVNProvisioningCertificationEnclave, "ISVSVN_PCE")
	require.Equal(
		t,
		"b8c38a06855ded89a028a0db48dbc68400000000000000000000000000000000",
		hex.EncodeToString(quote.Body.Basename[:]),
		"BASENAME",
	)

	require.Equal(
		t,
		"0207ffff010100000000000000000000",
		hex.EncodeToString(quote.Report.CPUSVN[:]),
		"CPUSVN",
	)
	require.EqualValues(t, 0x00000000, quote.Report.MiscSelect, "MISCSELECT")
	require.Equal(
		t,
		"07000000000000000700000000000000",
		hex.EncodeToString(quote.Report.Attributes[:]),
		"ATTRIBUTES",
	)
	require.Equal(
		t,
		"83d1607d933a8f1970fa30ac94cdb6921fd8ffb8414650af06fe63c008a4a9af",
		hex.EncodeToString(quote.Report.MRENCLAVE[:]),
		"MRENCLAVE",
	)
	require.Equal(
		t,
		"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e",
		hex.EncodeToString(quote.Report.MRSIGNER[:]),
		"MRSIGNER",
	)
	require.EqualValues(t, 0x0000, quote.Report.ISVProdID, "ISVPRODID")
	require.EqualValues(t, 0x0000, quote.Report.ISVSVN, "ISVSVN")
	require.Equal(
		t,
		"456b512d4964656e000000000000000000000000000000000000000000000000cf471ab9465815c56c21d467dab38abd01e2e1e308011085f3214bcb86a430af",
		hex.EncodeToString(quote.Report.ReportData[:]),
		"ReportData",
	)
}
