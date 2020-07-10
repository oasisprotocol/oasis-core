package ias

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQuote(t *testing.T) {
	// TODO: Generate and test production AVR without debug bit.
	SetAllowDebugEnclaves()
	defer UnsetAllowDebugEnclaves()

	raw, sig, certs := loadAVRv4(t)
	avr, err := DecodeAVR(raw, sig, certs, IntelTrustRoots, time.Now())
	require.NoError(t, err, "DecodeAVR")

	rawQuote := avr.ISVEnclaveQuoteBody
	var quote Quote
	err = quote.UnmarshalBinary(rawQuote)
	require.NoError(t, err, "UnmarshalBinary")

	require.EqualValues(t, 2, quote.Body.Version, "VERSION")
	require.Equal(t, SignatureLinkable, quote.Body.SignatureType, "SIGNATURE_TYPE")
	require.EqualValues(t, 0xbc5, quote.Body.GID, "GID")
	require.EqualValues(t, 0xb, quote.Body.ISVSVNQuotingEnclave, "ISVSVN_QE")
	require.EqualValues(t, 0xa, quote.Body.ISVSVNProvisioningCertificationEnclave, "ISVSVN_PCE")
	require.Equal(
		t,
		"14b5c60777a13ac77c732ce4d12d95b700000000000000000000000000000000",
		hex.EncodeToString(quote.Body.Basename[:]),
		"BASENAME",
	)

	require.Equal(
		t,
		"0f0f0205ff8007000000000000000000",
		hex.EncodeToString(quote.Report.CPUSVN[:]),
		"CPUSVN",
	)
	require.EqualValues(t, 0x00000000, quote.Report.MiscSelect, "MISCSELECT")
	require.EqualValues(t, 0x0000000000000007, quote.Report.Attributes.Flags, "ATTRIBUTES.FLAGS")
	require.EqualValues(t, 0x1f, quote.Report.Attributes.Xfrm, "ATTRIBUTES.XFRM")
	require.Equal(
		t,
		"92143ea742e1628677b5a8e280173b7264470bfb0611d520c2474aab9846168e",
		hex.EncodeToString(quote.Report.MRENCLAVE[:]),
		"MRENCLAVE",
	)
	require.Equal(
		t,
		"9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a",
		hex.EncodeToString(quote.Report.MRSIGNER[:]),
		"MRSIGNER",
	)
	require.EqualValues(t, 0x0000, quote.Report.ISVProdID, "ISVPRODID")
	require.EqualValues(t, 0x0000, quote.Report.ISVSVN, "ISVSVN")
	require.Equal(
		t,
		"6e90dd30d40b9813abb7f437a969de4fa2f9421df82519b9a507e3176cb3e1e062694e4d714241755450463268702f3066586134503373706c526b4c484a6630",
		hex.EncodeToString(quote.Report.ReportData[:]),
		"ReportData",
	)

	// Test Quote encoding.
	bQuote, err := quote.MarshalBinary()
	require.NoError(t, err, "EncodeQuote")
	require.Equal(t, rawQuote, bQuote, "BinaryQuote")
}
