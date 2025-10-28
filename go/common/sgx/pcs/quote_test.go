package pcs

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

func TestQuoteV3_ECDSA_P256_PCK_CertificateChain(t *testing.T) {
	require := require.New(t)

	rawQuote, err := os.ReadFile("testdata/quote_v3_ecdsa_p256_pck_chain.bin")
	require.NoError(err, "Read test vector")

	var quote Quote
	err = quote.UnmarshalBinary(rawQuote)
	require.NoError(err, "Parse quote")

	// Validate quote header.
	require.EqualValues(3, quote.header.Version())
	qh := quote.header.(*QuoteHeaderV3)
	require.EqualValues(9, qh.qeSvn)
	require.EqualValues(13, qh.pceSvn)
	require.EqualValues(QEVendorID_Intel, qh.qeVendorID[:])

	// Validate report body.
	report := quote.reportBody.(*SgxReport)
	require.EqualValues([]byte{8, 9, 14, 13, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, report.cpuSvn[:])
	require.EqualValues(0, report.miscSelect)
	require.EqualValues(sgx.AttributeInit|sgx.AttributeMode64Bit, report.attributes.Flags)
	require.EqualValues(3, report.attributes.Xfrm)
	require.EqualValues("68823bc62f409ee33a32ea270cfe45d4b19a6fb3c8570d7bc186cbe062398e8f", report.mrEnclave.String())
	require.EqualValues("9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a", report.mrSigner.String())
	require.EqualValues(0, report.isvProdID)
	require.EqualValues(0, report.isvSvn)
	require.EqualValues([]byte{2, 106, 105, 206, 217, 108, 62, 2, 149, 209, 109, 107, 56, 142, 5, 122, 19, 122, 20, 49, 150, 113, 102, 42, 88, 68, 199, 71, 47, 60, 98, 174, 14, 61, 63, 153, 183, 125, 216, 155, 15, 193, 67, 108, 79, 233, 104, 40, 57, 26, 82, 88, 138, 15, 136, 52, 85, 161, 139, 143, 88, 114, 227, 240}, report.reportData[:])

	// Validate quote signature.
	require.EqualValues(AttestationKeyECDSA_P256, quote.signature.AttestationKeyType())
	qs := quote.signature.(*QuoteSignatureECDSA_P256)
	require.EqualValues([]byte{8, 9, 14, 13, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, qs.qe.QEReport.cpuSvn[:])
	require.EqualValues(0, qs.qe.QEReport.miscSelect)
	require.EqualValues(sgx.AttributeInit|sgx.AttributeMode64Bit|sgx.AttributeProvisionKey, qs.qe.QEReport.attributes.Flags)
	require.EqualValues(231, qs.qe.QEReport.attributes.Xfrm)
	require.EqualValues(CertificationDataPCKCertificateChain, qs.qe.CertificationData.CertificationDataType())
	cd := qs.qe.CertificationData.(*CertificationData_PCKCertificateChain)
	require.Len(cd.CertificateChain, 3)

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

	now := time.Unix(1671497404, 0)
	verifiedQuote, err := quote.Verify(nil, now, &tcbBundle)
	require.NoError(err, "Verify quote signature")
	require.EqualValues("68823bc62f409ee33a32ea270cfe45d4b19a6fb3c8570d7bc186cbe062398e8f", verifiedQuote.Identity.MrEnclave.String())
	require.EqualValues("9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a", verifiedQuote.Identity.MrSigner.String())

	// Test X509 certificate has expired (not after 1891163521).
	now2a := time.Unix(1891163522, 0)
	_, err = quote.Verify(nil, now2a, &tcbBundle)
	require.Error(err, "Quote verification should fail for expired PCK certificates")
	require.ErrorContains(err, "pcs/quote: failed to verify PCK certificate chain: x509: certificate has expired or is not yet valid")

	// Test X509 certificate not yet valid (not before 1670238721).
	now2b := time.Unix(1670238720, 0)
	_, err = quote.Verify(nil, now2b, &tcbBundle)
	require.Error(err, "Quote verification should fail for PCK certificates not yet valid")
	require.ErrorContains(err, "pcs/quote: failed to verify PCK certificate chain: x509: certificate has expired or is not yet valid")

	// Test TCB info not yet valid (qe identity issue date 1671194736).
	now3 := time.Unix(1671194735, 0)
	_, err = quote.Verify(nil, now3, &tcbBundle)
	require.Error(err, "Quote verification should fail for TCB info not yet valid")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify QE identity: pcs/tcb: invalid QE identity: pcs/tcb: QE identity issue date in the future")

	// Test TCB info expired (qe identity issue date 1671194736 + validity period 30 * 24 * 60 * 60 = 1673786736).
	now4 := time.Unix(1673786737, 0)
	_, err = quote.Verify(nil, now4, &tcbBundle)
	require.Error(err, "Quote verification should fail for TCB info expired")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify QE identity: pcs/tcb: invalid QE identity: pcs/tcb: QE identity expired")

	// Test alternate validity from quote policy.
	now5 := time.Unix(1673786737, 0)
	quotePolicy := &QuotePolicy{
		TCBValidityPeriod: 90,
	}
	_, err = quote.Verify(quotePolicy, now5, &tcbBundle)
	require.NoError(err, "Quote verification should succeed with longer validity period")

	// Test minimum TCB evaluation data number.
	quotePolicy = &QuotePolicy{
		TCBValidityPeriod:          30,
		MinTCBEvaluationDataNumber: 100,
	}
	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.Error(err, "Quote verification should fail for invalid TCB evaluation data number")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify QE identity: pcs/tcb: invalid QE identity: pcs/tcb: invalid QE evaluation data number")

	// Test whitelisted FMSPC.
	quotePolicy = &QuotePolicy{
		TCBValidityPeriod: 90,
		FMSPCWhitelist:    []string{},
	}
	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.NoError(err, "Quote verification should succeed for whitelisted FMSPCs")

	quotePolicy = &QuotePolicy{
		TCBValidityPeriod: 90,
		FMSPCWhitelist:    []string{"00606A000000"},
	}
	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.NoError(err, "Quote verification should succeed for whitelisted FMSPCs")

	quotePolicy = &QuotePolicy{
		TCBValidityPeriod: 90,
		FMSPCWhitelist:    []string{"00606A000001"},
	}
	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.Error(err, "Quote verification should fail for non-whitelisted FMSPCs")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify TCB info: pcs/tcb: invalid TCB info: pcs/tcb: FMSPC is not whitelisted")

	// Test blacklisted FMSPC.
	quotePolicy = &QuotePolicy{
		TCBValidityPeriod: 90,
		FMSPCBlacklist:    []string{"00606A000000"},
	}
	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.Error(err, "Quote verification should fail for blacklisted FMSPCs")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify TCB info: pcs/tcb: invalid TCB info: pcs/tcb: FMSPC is blacklisted")

	// Test TCB info certificates missing.
	tcbBundle2 := TCBBundle{
		TCBInfo:      tcbInfo,
		QEIdentity:   qeIdentity,
		Certificates: nil,
	}
	_, err = quote.Verify(nil, now, &tcbBundle2)
	require.Error(err, "Quote verification should fail for bad TCB info certificates")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: unexpected certificate chain length: 0")

	// Test TCB info certificates bad.
	rawCertsBad, err := os.ReadFile("testdata/tcb_info_v3_fmspc_00606A000000_certs_bad.pem")
	require.NoError(err, "Read test vector")

	tcbBundle3 := TCBBundle{
		TCBInfo:      tcbInfo,
		QEIdentity:   qeIdentity,
		Certificates: rawCertsBad,
	}
	_, err = quote.Verify(nil, now, &tcbBundle3)
	require.Error(err, "Quote verification should fail for bad TCB info certificates")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify QE identity: pcs/tcb: invalid QE identity: pcs/tcb: TCB signature verification failed")

	// Test invalid TCB info signature.
	tcbBundle4 := TCBBundle{
		TCBInfo:      tcbInfo,
		QEIdentity:   qeIdentity,
		Certificates: rawCerts,
	}
	tcbBundle4.TCBInfo.TCBInfo = append([]byte{}, tcbBundle.TCBInfo.TCBInfo[:]...)
	tcbBundle4.TCBInfo.TCBInfo[16] = 'x'
	_, err = quote.Verify(nil, now, &tcbBundle4)
	require.Error(err, "Quote verification should fail for bad TCB info signature")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify TCB info: pcs/tcb: invalid TCB info: pcs/tcb: TCB signature verification failed")

	// Test invalid QE identity signature.
	tcbBundle5 := TCBBundle{
		TCBInfo:      tcbInfo,
		QEIdentity:   qeIdentity,
		Certificates: rawCerts,
	}
	tcbBundle5.QEIdentity.EnclaveIdentity = append([]byte{}, tcbBundle.QEIdentity.EnclaveIdentity[:]...)
	tcbBundle5.QEIdentity.EnclaveIdentity[22] = 'x'
	_, err = quote.Verify(nil, now, &tcbBundle5)
	require.Error(err, "Quote verification should fail for bad QE identity signature")
	require.ErrorContains(err, "pcs/quote: failed to verify TCB bundle: pcs/tcb: failed to verify QE identity: pcs/tcb: invalid QE identity: pcs/tcb: TCB signature verification failed")

	// Test quote bundle.
	quoteBundle := QuoteBundle{
		Quote: rawQuote,
		TCB:   tcbBundle,
	}

	verifiedQuote, err = quoteBundle.Verify(nil, now)
	require.NoError(err, "Verify quote bundle")
	require.EqualValues("68823bc62f409ee33a32ea270cfe45d4b19a6fb3c8570d7bc186cbe062398e8f", verifiedQuote.Identity.MrEnclave.String())
	require.EqualValues("9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a", verifiedQuote.Identity.MrSigner.String())

	// Test quote bundle serialization round-trip.
	rawQB := cbor.Marshal(quoteBundle)
	var quoteBundle2 QuoteBundle
	err = cbor.Unmarshal(rawQB, &quoteBundle2)
	require.NoError(err, "QuoteBundle serialization should round-trip")
	verifiedQuote, err = quoteBundle2.Verify(nil, now)
	require.NoError(err, "Verify deserialized quote bundle")
	require.EqualValues("68823bc62f409ee33a32ea270cfe45d4b19a6fb3c8570d7bc186cbe062398e8f", verifiedQuote.Identity.MrEnclave.String())
	require.EqualValues("9affcfae47b848ec2caf1c49b4b283531e1cc425f93582b36806e52a43d78d1a", verifiedQuote.Identity.MrSigner.String())
}

func TestQuoteV3_ECDSA_P256_EPPID(t *testing.T) {
	require := require.New(t)

	rawQuote, err := os.ReadFile("testdata/quote_v3_ecdsa_p256_eppid.bin")
	require.NoError(err, "Read test vector")

	var quote Quote
	err = quote.UnmarshalBinary(rawQuote)
	require.NoError(err, "Parse quote")

	// Validate quote header.
	require.EqualValues(3, quote.header.Version())
	qh := quote.header.(*QuoteHeaderV3)
	require.EqualValues(7, qh.qeSvn)
	require.EqualValues(12, qh.pceSvn)
	require.EqualValues(QEVendorID_Intel, qh.qeVendorID[:])

	// Validate report body.
	report := quote.reportBody.(*SgxReport)
	require.EqualValues([]byte{5, 5, 12, 12, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, report.cpuSvn[:])
	require.EqualValues(0, report.miscSelect)
	require.EqualValues(sgx.AttributeInit|sgx.AttributeMode64Bit, report.attributes.Flags)
	require.EqualValues(3, report.attributes.Xfrm)
	require.EqualValues("9479d8eddfd7b1b700319419551dc340f688c2ef519a5e18657ecf32981dbd9e", report.mrEnclave.String())
	require.EqualValues("4025dab7ebda1fbecc4e3637606e021214d0f41c6d0422fd378b2a8b88818459", report.mrSigner.String())
	require.EqualValues(0, report.isvProdID)
	require.EqualValues(0, report.isvSvn)
	require.EqualValues([]byte{88, 71, 160, 127, 98, 203, 186, 123, 157, 240, 227, 172, 25, 83, 16, 250, 226, 19, 77, 70, 182, 58, 130, 156, 76, 232, 128, 32, 45, 239, 29, 161, 119, 73, 117, 86, 119, 84, 116, 67, 70, 80, 103, 51, 101, 54, 75, 57, 74, 78, 66, 101, 57, 99, 73, 110, 103, 90, 53, 104, 115, 84, 100, 112}, report.reportData[:])

	// Validate quote signature.
	require.EqualValues(AttestationKeyECDSA_P256, quote.signature.AttestationKeyType())
	qs := quote.signature.(*QuoteSignatureECDSA_P256)
	require.EqualValues([]byte{5, 5, 12, 12, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, qs.qe.QEReport.cpuSvn[:])
	require.EqualValues(0, qs.qe.QEReport.miscSelect)
	require.EqualValues(sgx.AttributeInit|sgx.AttributeMode64Bit|sgx.AttributeProvisionKey, qs.qe.QEReport.attributes.Flags)
	require.EqualValues(231, qs.qe.QEReport.attributes.Xfrm)
	require.EqualValues(CertificationDataPPIDEncryptedRSA3072, qs.qe.CertificationData.CertificationDataType())
	cd := qs.qe.CertificationData.(*CertificationData_PPID)
	require.EqualValues([]byte{170, 122, 147, 8, 168, 67, 118, 90, 94, 46, 250, 136, 142, 250, 249, 234, 55, 249, 75, 95, 148, 7, 51, 235, 120, 64, 201, 20, 137, 74, 80, 246, 71, 64, 205, 196, 40, 48, 215, 102, 187, 193, 246, 61, 208, 252, 32, 227, 245, 53, 76, 83, 199, 186, 98, 183, 21, 60, 87, 128, 38, 233, 197, 138, 3, 8, 34, 138, 128, 162, 190, 95, 142, 223, 243, 12, 196, 111, 24, 153, 190, 163, 6, 33, 173, 13, 76, 72, 18, 51, 152, 234, 103, 231, 58, 14, 217, 35, 77, 134, 1, 220, 57, 154, 221, 221, 235, 203, 131, 154, 113, 78, 29, 182, 151, 119, 82, 98, 130, 74, 219, 242, 248, 37, 224, 232, 171, 163, 115, 22, 15, 240, 158, 159, 252, 207, 113, 61, 62, 65, 109, 116, 67, 168, 195, 165, 198, 125, 56, 62, 116, 148, 233, 223, 41, 152, 141, 225, 36, 48, 144, 195, 86, 148, 136, 139, 162, 31, 69, 238, 139, 188, 221, 191, 7, 197, 57, 232, 174, 135, 47, 205, 171, 251, 38, 40, 116, 227, 76, 101, 104, 161, 42, 118, 145, 155, 26, 168, 205, 124, 89, 78, 226, 138, 88, 11, 33, 134, 39, 203, 73, 109, 250, 43, 139, 53, 3, 50, 57, 47, 223, 219, 63, 87, 116, 227, 204, 29, 5, 163, 85, 55, 120, 56, 185, 231, 109, 29, 72, 199, 22, 170, 248, 24, 254, 243, 105, 173, 228, 146, 232, 40, 50, 238, 184, 46, 165, 185, 172, 221, 188, 243, 187, 254, 32, 60, 58, 119, 43, 117, 247, 123, 11, 213, 106, 177, 199, 233, 160, 243, 129, 46, 149, 228, 10, 192, 142, 181, 89, 213, 143, 219, 237, 34, 18, 157, 19, 120, 128, 226, 14, 222, 10, 68, 176, 193, 69, 142, 240, 38, 191, 139, 85, 23, 117, 232, 111, 192, 123, 57, 60, 174, 9, 97, 56, 115, 106, 207, 217, 58, 149, 40, 250, 176, 238, 31, 253, 110, 184, 12, 125, 197, 94, 120, 220, 3, 242, 69, 35, 168, 44, 157, 5, 250, 125, 189, 213, 8, 30, 89, 146, 108, 191, 206, 215, 214, 114, 178, 124, 152, 168, 160, 223, 13, 19, 238, 20, 102, 72, 84, 98, 173, 223, 192}, cd.PPID[:])
	require.EqualValues([]byte{5, 5, 12, 12, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, cd.CPUSVN[:])
	require.EqualValues(12, cd.PCESVN)
	require.EqualValues(0, cd.PCEID)

	_, err = quote.Verify(nil, time.Now(), nil)
	require.Error(err, "Verify quote signature (should fail for PPID auth)")
}

func TestQuoteV4_TDX_ECDSA_P256(t *testing.T) {
	require := require.New(t)

	rawQuote, err := os.ReadFile("testdata/quote_v4_tdx_ecdsa_p256.bin")
	require.NoError(err, "Read test vector")

	var quote Quote
	err = quote.UnmarshalBinary(rawQuote)
	require.NoError(err, "Parse quote")

	// Validate quote header.
	require.EqualValues(4, quote.header.Version())

	// Validate TD report.
	report := quote.reportBody.(*TdReport)
	require.EqualValues(TdAttributeSeptVeDisable, report.tdAttributes)

	// Prepare TCB bundle needed for verification.
	rawTCBInfo, err := os.ReadFile("testdata/tcb_info_v3_tdx_fmspc_C0806F000000.json") // From PCS V4 response.
	require.NoError(err, "Read test vector")
	rawCerts, err := os.ReadFile("testdata/tcb_info_v3_fmspc_00606A000000_certs.pem") // From PCS V4 response (TCB-Info-Issuer-Chain header).
	require.NoError(err, "Read test vector")
	rawQEIdentity, err := os.ReadFile("testdata/qe_identity_v2_tdx2.json") // From PCS V4 response.
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
	quotePolicy := &QuotePolicy{
		TCBValidityPeriod:          30,
		MinTCBEvaluationDataNumber: 12,
		TDX:                        &TdxQuotePolicy{}, // Allow TDX.
	}

	now := time.Unix(1725263032, 0)
	verifiedQuote, err := quote.Verify(quotePolicy, now, &tcbBundle)
	require.NoError(err, "Verify quote signature")

	require.EqualValues("0000000000000000000000000000000000000000000000000000000000000000", verifiedQuote.Identity.MrSigner.String())
	require.EqualValues("63d522d975f7de879a8f3368b4f32dd1e8db635f5a24b651ce8ff81705028813", verifiedQuote.Identity.MrEnclave.String())

	// Ensure TDX quote verification fails in case it is not allowed.
	quotePolicy = &QuotePolicy{
		TCBValidityPeriod:          30,
		MinTCBEvaluationDataNumber: 12,
	}

	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.ErrorContains(err, "TEE type not allowed", "Verify quote signature")

	// Ensure TDX quote verification fails in case the given TDX Module is not allowed.
	var mrSignerSeam [48]byte
	mrSignerSeam[0] = 1

	quotePolicy = &QuotePolicy{
		TCBValidityPeriod:          30,
		MinTCBEvaluationDataNumber: 12,
		TDX: &TdxQuotePolicy{
			AllowedTdxModules: []TdxModulePolicy{
				{
					MrSignerSeam: mrSignerSeam,
				},
			},
		},
	}

	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.ErrorContains(err, "TDX module not allowed", "Verify quote signature")
}

func TestQuoteV4_TDX_ECDSA_P256_OutOfDate(t *testing.T) {
	require := require.New(t)

	rawQuote, err := os.ReadFile("testdata/quote_v4_tdx_ecdsa_p256_out_of_date.bin")
	require.NoError(err, "Read test vector")

	var quote Quote
	err = quote.UnmarshalBinary(rawQuote)
	require.NoError(err, "Parse quote")

	// Prepare TCB bundle needed for verification.
	rawTCBInfo, err := os.ReadFile("testdata/tcb_info_v3_tdx_fmspc_50806F000000.json") // From PCS V4 response.
	require.NoError(err, "Read test vector")
	rawCerts, err := os.ReadFile("testdata/tcb_info_v3_fmspc_00606A000000_certs.pem") // From PCS V4 response (TCB-Info-Issuer-Chain header).
	require.NoError(err, "Read test vector")
	rawQEIdentity, err := os.ReadFile("testdata/qe_identity_v2_tdx.json") // From PCS V4 response.
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
	quotePolicy := &QuotePolicy{
		TCBValidityPeriod:          30,
		MinTCBEvaluationDataNumber: 12,
		TDX:                        &TdxQuotePolicy{}, // Allow TDX.
	}

	now := time.Unix(1687091776, 0)
	_, err = quote.Verify(quotePolicy, now, &tcbBundle)
	require.ErrorContains(err, "TCB level not supported", "Verify quote signature") // The quote is out of date.
}

func TestQuoteV4_TDX_ECDSA_P256_TrailingData(t *testing.T) {
	require := require.New(t)

	rawQuote, err := os.ReadFile("testdata/quote_v4_tdx_ecdsa_p256_trailing.bin")
	require.NoError(err, "Read test vector")

	var quote Quote
	err = quote.UnmarshalBinary(rawQuote)
	require.Error(err, "Parse quote (trailing data not allowed)")

	size, err := quote.UnmarshalBinaryWithTrailing(rawQuote, true)
	require.NoError(err, "Parse quote (trailing data allowed)")

	err = quote.UnmarshalBinary(rawQuote[:size])
	require.NoError(err, "Parse quote (trimmed)")
}

func FuzzQuoteUnmarshal(f *testing.F) {
	// Seed corpus.
	raw1, _ := os.ReadFile("testdata/quote_v3_ecdsa_p256_pck_chain.bin")
	f.Add(raw1)
	raw2, _ := os.ReadFile("testdata/quote_v3_ecdsa_p256_eppid.bin")
	f.Add(raw2)
	raw3, _ := os.ReadFile("testdata/quote_v4_tdx_ecdsa_p256.bin")
	f.Add(raw3)
	raw4, _ := os.ReadFile("testdata/quote_v4_tdx_ecdsa_p256_out_of_date.bin")
	f.Add(raw4)

	// Fuzzing.
	f.Fuzz(func(_ *testing.T, data []byte) {
		var quote Quote
		_ = quote.UnmarshalBinary(data)
	})
}
