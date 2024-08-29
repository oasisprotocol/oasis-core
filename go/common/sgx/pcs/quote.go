package pcs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

const (
	// quoteHeaderLen is the length of the quote header in bytes.
	quoteHeaderLen = 48

	// reportBodySgxLen is the length of the SGX report in bytes.
	reportBodySgxLen = 384
	// reportBodyTdLen is the length of the TDX TD report in bytes.
	reportBodyTdLen = 584

	// quoteSigSizeLen is the length of the quote signature size field in bytes.
	quoteSigSizeLen = 4

	// quoteSigEcdsaP256MinLen is the minimum length of the ECDSA-P256 quote signature in bytes.
	quoteSigEcdsaP256MinLen = 584

	// ppidDataLen is the PPID certification data length in bytes.
	ppidDataLen = 404

	// DefaultMinTCBEvaluationDataNumber is the default minimum TCB evaluation data number.
	DefaultMinTCBEvaluationDataNumber = 12 // As of 2022-08-01.
)

// Quote is an enclave quote.
type Quote struct {
	header     QuoteHeader
	reportBody ReportBody
	signature  QuoteSignature
}

const (
	quoteVersionV3 = 3
	quoteVersionV4 = 4
)

// UnmarshalBinary decodes a Quote from a byte array.
func (q *Quote) UnmarshalBinary(data []byte) error {
	if len(data) < quoteHeaderLen+reportBodySgxLen+quoteSigSizeLen {
		return fmt.Errorf("pcs/quote: invalid quote length")
	}

	// Quote Header.
	var offset int
	version := binary.LittleEndian.Uint16(data[0:])
	switch version {
	case quoteVersionV3:
		var qh QuoteHeaderV3
		if err := qh.UnmarshalBinary(data[offset : offset+quoteHeaderLen]); err != nil {
			return err
		}
		q.header = &qh
	case quoteVersionV4:
		var qh QuoteHeaderV4
		if err := qh.UnmarshalBinary(data[offset : offset+quoteHeaderLen]); err != nil {
			return err
		}
		q.header = &qh
	default:
		return fmt.Errorf("pcs/quote: unsupported quote version %d", version)
	}
	offset += quoteHeaderLen

	if !bytes.Equal(q.header.QEVendorID(), QEVendorID_Intel) {
		return fmt.Errorf("pcs/quote: unsupported QE vendor: %X", q.header.QEVendorID())
	}

	// Report body.
	switch q.header.TeeType() {
	case TeeTypeSGX:
		var report SgxReport
		if err := report.UnmarshalBinary(data[offset : offset+reportBodySgxLen]); err != nil {
			return err
		}
		q.reportBody = &report
		offset += reportBodySgxLen
	case TeeTypeTDX:
		if len(data) < offset+reportBodyTdLen+quoteSigSizeLen {
			return fmt.Errorf("pcs/quote: invalid quote length")
		}

		var report TdReport
		if err := report.UnmarshalBinary(data[offset : offset+reportBodyTdLen]); err != nil {
			return err
		}
		q.reportBody = &report
		offset += reportBodyTdLen
	}

	// Quote Signature Length.
	sigLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += quoteSigSizeLen
	if len(data) != offset+sigLen {
		return fmt.Errorf("pcs/quote: unexpected trailing data")
	}

	// Quote Signature.
	switch q.header.AttestationKeyType() {
	case AttestationKeyECDSA_P256:
		var qs QuoteSignatureECDSA_P256
		if err := qs.UnmarshalBinary(q.header.Version(), data[offset:offset+sigLen]); err != nil {
			return err
		}
		q.signature = &qs
	default:
		return fmt.Errorf("pcs/quote: unsupported attestation key type: %s", q.header.AttestationKeyType())
	}

	return nil
}

// Verify verifies the quote.
//
// In case of successful verification it returns the TCB level.
func (q *Quote) Verify(policy *QuotePolicy, ts time.Time, tcb *TCBBundle) (*sgx.VerifiedQuote, error) {
	if policy == nil {
		policy = &QuotePolicy{
			TCBValidityPeriod:          30,
			MinTCBEvaluationDataNumber: DefaultMinTCBEvaluationDataNumber,
			FMSPCBlacklist:             []string{},
		}
	}

	if policy.Disabled {
		return nil, fmt.Errorf("pcs/quote: PCS quotes are disabled by policy")
	}

	switch q.header.TeeType() {
	case TeeTypeSGX:
		report, ok := q.reportBody.(*SgxReport)
		if !ok {
			return nil, fmt.Errorf("pcs/quote: mismatched report body and TEE type")
		}
		if mrSignerBlacklist[report.mrSigner] {
			return nil, fmt.Errorf("pcs/quote: blacklisted MRSIGNER")
		}

		isDebug := report.attributes.Flags.Contains(sgx.AttributeDebug)
		if unsafeAllowDebugEnclaves != isDebug {
			// Debug enclaves are only allowed in debug mode, prod enclaves in prod mode.
			// A mismatch is an error.
			return nil, fmt.Errorf("pcs/quote: disallowed debug/production enclave/mode combination")
		}
	case TeeTypeTDX:
		report, ok := q.reportBody.(*TdReport)
		if !ok {
			return nil, fmt.Errorf("pcs/quote: mismatched report body and TEE type")
		}

		isDebug := report.tdAttributes.Contains(TdAttributeDebug)
		if unsafeAllowDebugEnclaves != isDebug {
			// Debug TDs are only allowed in debug mode, prod TDs in prod mode.
			// A mismatch is an error.
			return nil, fmt.Errorf("pcs/quote: disallowed debug/production enclave/mode combination")
		}

		// Verify report against TDX policy.
		if policy.TDX == nil {
			return nil, fmt.Errorf("pcs/quote: TEE type not allowed")
		}
		if err := policy.TDX.Verify(report); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("pcs/quote: unsupported TEE type: %X", q.header.TeeType())
	}

	if !unsafeSkipVerify {
		err := q.signature.Verify(q.header, q.reportBody, ts, tcb, policy)
		if err != nil {
			return nil, err
		}
	}

	return &sgx.VerifiedQuote{
		ReportData: q.reportBody.ReportData(),
		Identity:   q.reportBody.AsEnclaveIdentity(),
	}, nil
}

// Signature returns the quote signature.
func (q *Quote) Signature() QuoteSignature {
	return q.signature
}

// TeeType is the TEE type.
type TeeType uint32

const (
	TeeTypeSGX TeeType = 0x00000000
	TeeTypeTDX TeeType = 0x00000081
)

// QuoteHeader is the quote header interface.
type QuoteHeader interface {
	// Version returns the quote version.
	Version() uint16

	// TeeType returns the TEE type.
	TeeType() TeeType

	// QEVendorID returns the QE vendor ID.
	QEVendorID() []byte

	// AttestationKeyType returns the quote attestation key type.
	AttestationKeyType() AttestationKeyType

	// ReportBodyLength returns the length of the report body field.
	ReportBodyLength() int

	// Raw returns the raw quote header bytes.
	Raw() []byte
}

// QuoteHeaderV3 is a V3 quote header.
type QuoteHeaderV3 struct {
	qeSvn      uint16
	pceSvn     uint16
	qeVendorID [16]byte
	userData   [20]byte

	attestationKeyType AttestationKeyType
	raw                []byte
}

// UnmarshalBinary decodes QuoteHeaderV3 from a byte array.
func (qh *QuoteHeaderV3) UnmarshalBinary(data []byte) error {
	if len(data) != quoteHeaderLen {
		return fmt.Errorf("pcs/quote: invalid quote header length")
	}

	if version := binary.LittleEndian.Uint16(data[0:]); version != quoteVersionV3 {
		return fmt.Errorf("pcs/quote: invalid quote version")
	}

	qh.attestationKeyType = AttestationKeyType(binary.LittleEndian.Uint16(data[2:]))

	reserved := binary.LittleEndian.Uint32(data[4:])
	if reserved != 0 {
		return fmt.Errorf("pcs/quote: data in reserved field")
	}

	qh.qeSvn = binary.LittleEndian.Uint16(data[8:])
	qh.pceSvn = binary.LittleEndian.Uint16(data[10:])
	copy(qh.qeVendorID[:], data[12:])
	copy(qh.userData[:], data[28:])

	qh.raw = data[:quoteHeaderLen]

	return nil
}

// Version returns the quote version.
func (qh *QuoteHeaderV3) Version() uint16 {
	return quoteVersionV3
}

// TeeType returns the TEE type.
func (qh *QuoteHeaderV3) TeeType() TeeType {
	return TeeTypeSGX
}

// QEVendorID returns the QE vendor ID.
func (qh *QuoteHeaderV3) QEVendorID() []byte {
	return qh.qeVendorID[:]
}

// AttestationKeyType returns the quote attestation key type.
func (qh *QuoteHeaderV3) AttestationKeyType() AttestationKeyType {
	return qh.attestationKeyType
}

// ReportBodyLength returns the length of the report body field.
func (qh *QuoteHeaderV3) ReportBodyLength() int {
	return reportBodySgxLen
}

// Raw returns the raw quote header bytes.
func (qh *QuoteHeaderV3) Raw() []byte {
	return qh.raw
}

// QuoteHeaderV4 is a V4 quote header.
type QuoteHeaderV4 struct {
	teeType    TeeType
	qeVendorID [16]byte
	userData   [20]byte

	attestationKeyType AttestationKeyType
	raw                []byte
}

// UnmarshalBinary decodes QuoteHeaderV4 from a byte array.
func (qh *QuoteHeaderV4) UnmarshalBinary(data []byte) error {
	if len(data) != quoteHeaderLen {
		return fmt.Errorf("pcs/quote: invalid quote header length")
	}

	if version := binary.LittleEndian.Uint16(data[0:]); version != quoteVersionV4 {
		return fmt.Errorf("pcs/quote: invalid quote version")
	}

	qh.attestationKeyType = AttestationKeyType(binary.LittleEndian.Uint16(data[2:]))

	qh.teeType = TeeType(binary.LittleEndian.Uint32(data[4:]))
	switch qh.teeType {
	case TeeTypeSGX, TeeTypeTDX:
	default:
		return fmt.Errorf("pcs/quote: unsupported TEE type: %d", qh.teeType)
	}

	reserved1 := binary.LittleEndian.Uint16(data[8:])
	reserved2 := binary.LittleEndian.Uint16(data[10:])
	if reserved1 != 0 || reserved2 != 0 {
		return fmt.Errorf("pcs/quote: data in reserved field")
	}

	copy(qh.qeVendorID[:], data[12:])
	copy(qh.userData[:], data[28:])

	qh.raw = data[:quoteHeaderLen]

	return nil
}

// Version returns the quote version.
func (qh *QuoteHeaderV4) Version() uint16 {
	return quoteVersionV4
}

// TeeType returns the TEE type.
func (qh *QuoteHeaderV4) TeeType() TeeType {
	return qh.teeType
}

// QEVendorID returns the QE vendor ID.
func (qh *QuoteHeaderV4) QEVendorID() []byte {
	return qh.qeVendorID[:]
}

// AttestationKeyType returns the quote attestation key type.
func (qh *QuoteHeaderV4) AttestationKeyType() AttestationKeyType {
	return qh.attestationKeyType
}

// ReportBodyLength returns the length of the report body field.
func (qh *QuoteHeaderV4) ReportBodyLength() int {
	switch qh.teeType {
	case TeeTypeSGX:
		return reportBodySgxLen
	case TeeTypeTDX:
		return reportBodyTdLen
	default:
		return 0
	}
}

// Raw returns the raw quote header bytes.
func (qh *QuoteHeaderV4) Raw() []byte {
	return qh.raw
}

// QEVendorID_Intel is the Quoting Enclave vendor ID for Intel (939A7233F79C4CA9940A0DB3957F0607).
var QEVendorID_Intel = []byte{0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07} // nolint: revive

// SGXExtension is an ASN1 SGX extension.
type SGXExtension struct {
	Id    asn1.ObjectIdentifier // nolint: revive
	Value asn1.RawValue
}

var (
	// PCK_SGX_Extensions is the ASN1 Object Identifier for the SGX Extensions X509 extension.
	PCK_SGX_Extensions = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1} // nolint: revive

	// PCK_SGX_Extensions_FMSPC is the ASN1 Object Identifier for the FMSPC SGX Extension.
	PCK_SGX_Extensions_FMSPC = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4} // nolint: revive

	// PCK_SGX_Extensions_TCB is the ASN1 Object Identifier for the TCB SGX Extension.
	PCK_SGX_Extensions_TCB = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 2} // nolint: revive
)

// AttestationKeyType is the attestation key type.
type AttestationKeyType uint16

const (
	// AttestationKeyECDSA_P256 is the ECDSA-P256 attestation key type.
	AttestationKeyECDSA_P256 AttestationKeyType = 2 // nolint: revive
)

// String returns a string representation of the attestation key type.
func (kt AttestationKeyType) String() string {
	switch kt {
	case AttestationKeyECDSA_P256:
		return "ECDSA-P256"
	default:
		return fmt.Sprintf("[unknown (%x)]", uint16(kt))
	}
}

// QuoteSignature is a quote signature.
type QuoteSignature interface {
	// AttestationKeyType returns the type of the attestation key used in this quote signature.
	AttestationKeyType() AttestationKeyType

	// Verify verifies the quote signature of the header and ISV report.
	Verify(
		header QuoteHeader,
		reportBody ReportBody,
		ts time.Time,
		tcb *TCBBundle,
		policy *QuotePolicy,
	) error
}

// CertificationData_QEReport is the QE report certification data that contains nested certification
// data. This kind is implicit in v3 quotes and explicit via an additional envelope in v4 quotes.
type CertificationData_QEReport struct { //nolint: revive
	QEReport           SgxReport
	QEReportSignature  SignatureECDSA_P256
	AuthenticationData []byte
	CertificationData  CertificationData
}

// CertificationDataType returns the certification data type.
func (qe *CertificationData_QEReport) CertificationDataType() CertificationDataType {
	return CertificationDataQEReport
}

// UnmarshalBinary decodes CertificationData_QEReport from a byte array.
func (qe *CertificationData_QEReport) UnmarshalBinary(data []byte) error {
	if len(data) < reportBodySgxLen {
		return fmt.Errorf("pcs/quote: malformed certification data")
	}

	var offset int
	if err := qe.QEReport.UnmarshalBinary(data[offset : offset+reportBodySgxLen]); err != nil {
		return err
	}
	offset += reportBodySgxLen

	if len(data) < offset+len(qe.QEReportSignature[:]) {
		return fmt.Errorf("pcs/quote: malformed certification data")
	}
	copy(qe.QEReportSignature[:], data[offset:])
	offset += len(qe.QEReportSignature)

	authDataSize := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+authDataSize {
		return fmt.Errorf("pcs/quote: invalid ECDSA-P256 quote signature authentication data size")
	}
	qe.AuthenticationData = make([]byte, authDataSize)
	copy(qe.AuthenticationData[:], data[offset:offset+authDataSize])
	offset += authDataSize

	certificationDataType := CertificationDataType(binary.LittleEndian.Uint16(data[offset:]))
	certDataSize := int(binary.LittleEndian.Uint32(data[offset+2:]))
	if len(data) < offset+6+certDataSize {
		return fmt.Errorf("pcs/quote: invalid ECDSA-P256 quote signature certification data size")
	}
	certData := data[offset+6 : offset+6+certDataSize]

	switch certificationDataType {
	case CertificationDataPPIDCleartext, CertificationDataPPIDEncryptedRSA2048, CertificationDataPPIDEncryptedRSA3072:
		var cd CertificationData_PPID
		if err := cd.UnmarshalBinary(certData); err != nil {
			return err
		}
		cd.subtype = certificationDataType
		qe.CertificationData = &cd
	case CertificationDataPCKCertificateChain:
		var cd CertificationData_PCKCertificateChain
		if err := cd.UnmarshalBinary(certData); err != nil {
			return err
		}
		qe.CertificationData = &cd
	default:
		return fmt.Errorf("pcs/quote: unsupported certification data type: %s", certificationDataType)
	}

	return nil
}

func (qe *CertificationData_QEReport) verifyCertificateChain(ts time.Time) (*x509.Certificate, error) {
	cd, ok := qe.CertificationData.(*CertificationData_PCKCertificateChain)
	if !ok {
		return nil, fmt.Errorf("pcs/quote: no PCK certificate chain in quote")
	}
	if len(cd.CertificateChain) != 3 {
		return nil, fmt.Errorf("pcs/quote: unexpected certificate chain length: %d", len(cd.CertificateChain))
	}

	leafCert, intermediateCert, rootCert := cd.CertificateChain[0], cd.CertificateChain[1], cd.CertificateChain[2]
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	certChains, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         IntelTrustRoots,
		Intermediates: intermediates,
		CurrentTime:   ts,
	})
	if err != nil {
		return nil, fmt.Errorf("pcs/quote: failed to verify PCK certificate chain: %w", err)
	}
	if len(certChains) != 1 {
		return nil, fmt.Errorf("pcs/quote: unexpected number of chains: %d", len(certChains))
	}
	chain := certChains[0]

	if !chain[len(chain)-1].Equal(rootCert) {
		return nil, fmt.Errorf("pcs/quote: unexpected root in certificate chain")
	}

	return leafCert, nil
}

// PCKInfo contains information extracted from the PCK certificate.
type PCKInfo struct {
	PublicKey  *ecdsa.PublicKey
	FMSPC      []byte
	TCBCompSVN [16]int32
	PCESVN     uint16
	CPUSVN     [16]byte
}

// verifyPCK verifies the PCK certificate and returns the extracted information.
func (qe *CertificationData_QEReport) verifyPCK(ts time.Time) (*PCKInfo, error) {
	// Verify PCK certificate chain.
	leafCert, err := qe.verifyCertificateChain(ts)
	if err != nil {
		return nil, err
	}

	// Get PCK public key and FMSPC from PCK certificate.
	var pckInfo PCKInfo
	pk, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("pcs/quote: PCK certificate with non-ECDSA signature scheme")
	}
	pckInfo.PublicKey = pk

	for _, ext := range leafCert.Extensions {
		if !ext.Id.Equal(PCK_SGX_Extensions) {
			continue
		}

		// The SGX Extensions extension contains an ASN.1 SEQUENCE.
		var sgxExts []SGXExtension
		if _, err = asn1.Unmarshal(ext.Value, &sgxExts); err != nil {
			return nil, fmt.Errorf("pcs/quote: bad X509 SGX extensions: %w", err)
		}

		for _, sgxExt := range sgxExts {
			switch {
			case sgxExt.Id.Equal(PCK_SGX_Extensions_FMSPC):
				// FMSPC
				if _, err = asn1.Unmarshal(sgxExt.Value.FullBytes, &pckInfo.FMSPC); err != nil {
					return nil, fmt.Errorf("pcs/quote: bad FMSPC value: %w", err)
				}
				if len(pckInfo.FMSPC) != 6 {
					return nil, fmt.Errorf("pcs/quote: bad FMSPC length: %d", len(pckInfo.FMSPC))
				}
			case sgxExt.Id.Equal(PCK_SGX_Extensions_TCB):
				// TCB
				var tcbExts []SGXExtension
				if _, err = asn1.Unmarshal(sgxExt.Value.FullBytes, &tcbExts); err != nil {
					return nil, fmt.Errorf("pcs/quote: bad TCB value: %w", err)
				}

				for _, tcbExt := range tcbExts {
					switch compId := tcbExt.Id[len(tcbExt.Id)-1]; { // nolint: revive
					case compId >= 1 && compId <= 16:
						// TCB Component SVNs
						if _, err = asn1.Unmarshal(tcbExt.Value.FullBytes, &pckInfo.TCBCompSVN[compId-1]); err != nil {
							return nil, fmt.Errorf("pcs/quote: bad TCB component '%d' SVN value: %w", compId, err)
						}
					case compId == 17:
						// PCESVN
						var pcesvn int32
						if _, err = asn1.Unmarshal(tcbExt.Value.FullBytes, &pcesvn); err != nil {
							return nil, fmt.Errorf("pcs/quote: bad PCESVN: %w", err)
						}
						if pcesvn < 0 || pcesvn > math.MaxUint16 {
							return nil, fmt.Errorf("pcs/quote: bad PCESVN value: %d (not uint16)", pcesvn)
						}
						pckInfo.PCESVN = uint16(pcesvn)
					case compId == 18:
						// CPUSVN
						var cpusvnSlice []byte
						if _, err = asn1.Unmarshal(tcbExt.Value.FullBytes, &cpusvnSlice); err != nil {
							return nil, fmt.Errorf("pcs/quote: bad CPUSVN: %w", err)
						}
						copy(pckInfo.CPUSVN[:], cpusvnSlice)
					}
				}
			}
		}
		break
	}
	if pckInfo.FMSPC == nil {
		return nil, fmt.Errorf("pcs/quote: missing FMSPC field")
	}

	return &pckInfo, nil
}

// verify verifies the quote signature.
func (qe *CertificationData_QEReport) verify(
	attestationPublicKey []byte,
	header QuoteHeader,
	reportBody ReportBody,
	ts time.Time,
	tcb *TCBBundle,
	policy *QuotePolicy,
) error {
	// Verify PCK certificate chain and extract relevant information (e.g. public key and FMSPC).
	pckInfo, err := qe.verifyPCK(ts)
	if err != nil {
		return err
	}

	// Verify QE report signature using PCK public key.
	reportHash := sha256.Sum256(qe.QEReport.raw)
	if !qe.QEReportSignature.Verify(pckInfo.PublicKey, reportHash[:]) {
		return fmt.Errorf("pcs/quote: failed to verify QE report signature using PCK public key")
	}

	// Verify QE report data. First 32 bytes MUST be:
	//   SHA-256(AttestationPublicKey || AuthenticationData)
	// and the remaining 32 bytes MUST be zero.
	h := sha256.New()
	h.Write(attestationPublicKey)
	h.Write(qe.AuthenticationData[:])
	expectedHash := h.Sum(nil)

	if !bytes.Equal(qe.QEReport.reportData[:32], expectedHash) {
		return fmt.Errorf("pcs/quote: QE report data does not match expected value")
	}
	var allZeros [32]byte
	if !bytes.Equal(qe.QEReport.reportData[32:], allZeros[:]) {
		return fmt.Errorf("pcs/quote: QE report data does not match expected value")
	}

	// Verify TCB and QE identity.
	if tcb == nil {
		return fmt.Errorf("pcs/quote: missing TCB bundle")
	}
	var tdxCompSvn *[16]byte
	if header.TeeType() == TeeTypeTDX {
		// Extract TEE TCB SVN for TDX.
		tdxCompSvn = &reportBody.(*TdReport).teeTcbSvn
	}
	err = tcb.Verify(header.TeeType(), ts, policy, pckInfo.FMSPC, pckInfo.TCBCompSVN, tdxCompSvn, pckInfo.PCESVN, &qe.QEReport)
	if err != nil {
		return fmt.Errorf("pcs/quote: failed to verify TCB bundle: %w", err)
	}

	return nil
}

// QuoteSignatureECDSA_P256 is an ECDSA-P256 quote signature.
type QuoteSignatureECDSA_P256 struct { // nolint: revive
	signature            SignatureECDSA_P256
	attestationPublicKey [64]byte

	qe *CertificationData_QEReport
}

// AttestationKeyType returns the type of the attestation key used in this quote signature.
func (qs *QuoteSignatureECDSA_P256) AttestationKeyType() AttestationKeyType {
	return AttestationKeyECDSA_P256
}

// UnmarshalBinary decodes QuoteSignatureECDSA_P256 from a byte array.
func (qs *QuoteSignatureECDSA_P256) UnmarshalBinary(version uint16, data []byte) error {
	if len(data) < quoteSigEcdsaP256MinLen {
		return fmt.Errorf("pcs/quote: invalid ECDSA-P256 quote signature length")
	}

	var offset int
	copy(qs.signature[:], data[0:])
	offset += len(qs.signature)

	copy(qs.attestationPublicKey[:], data[offset:])
	offset += len(qs.attestationPublicKey)

	// In version 4 quotes, there is an intermediate certification data tuple.
	if version == quoteVersionV4 {
		certificationDataType := CertificationDataType(binary.LittleEndian.Uint16(data[offset:]))
		certDataSize := int(binary.LittleEndian.Uint32(data[offset+2:]))
		offset += 6
		if len(data[offset:]) != certDataSize {
			return fmt.Errorf("pcs/quote: invalid ECDSA-P256 quote signature certification data size")
		}
		if certificationDataType != CertificationDataQEReport {
			return fmt.Errorf("pcs/quote: unexpected certification data")
		}
	}

	var qe CertificationData_QEReport
	if err := qe.UnmarshalBinary(data[offset:]); err != nil {
		return err
	}
	qs.qe = &qe

	return nil
}

// Verify verifies the quote signature.
func (qs *QuoteSignatureECDSA_P256) Verify(
	header QuoteHeader,
	reportBody ReportBody,
	ts time.Time,
	tcb *TCBBundle,
	policy *QuotePolicy,
) error {
	// Verify attestation public key used by QE.
	if err := qs.qe.verify(qs.attestationPublicKey[:], header, reportBody, ts, tcb, policy); err != nil {
		return err
	}

	// Verify quote header and report body signature.
	attPkWithTag := append([]byte{0x04}, qs.attestationPublicKey[:]...) // Add SEC 1 tag (uncompressed).
	x, y := elliptic.Unmarshal(elliptic.P256(), attPkWithTag)           //nolint:staticcheck
	if x == nil {
		return fmt.Errorf("pcs/quote: invalid attestation public key")
	}
	attPk := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	h := sha256.New()
	h.Write(header.Raw())
	h.Write(reportBody.Raw())
	expectedHash := h.Sum(nil)

	if !qs.signature.Verify(&attPk, expectedHash) {
		return fmt.Errorf("pcs/quote: failed to verify quote signature")
	}

	return nil
}

// CertificationData returns the certification data.
func (qs *QuoteSignatureECDSA_P256) CertificationData() CertificationData {
	return qs.qe.CertificationData
}

// VerifyPCK verifies the PCK certificate and returns the extracted information.
func (qs *QuoteSignatureECDSA_P256) VerifyPCK(ts time.Time) (*PCKInfo, error) {
	return qs.qe.verifyPCK(ts)
}

// SignatureECDSA_P256 is an ECDSA-P256 signature in the form r || s.
type SignatureECDSA_P256 [64]byte // nolint: revive

// UnmarshalHex decodes the signature from a hex-encoded string.
func (ec *SignatureECDSA_P256) UnmarshalHex(data string) error {
	var (
		b   []byte
		err error
	)
	if b, err = hex.DecodeString(data); err != nil {
		return err
	}
	if len(b) != 64 {
		return fmt.Errorf("malformed signature")
	}
	copy(ec[:], b)
	return nil
}

// Verify verifies the signature of hash using the passed public key.
func (ec *SignatureECDSA_P256) Verify(pk *ecdsa.PublicKey, hash []byte) bool {
	var r, s big.Int
	r.SetBytes(ec[:32])
	s.SetBytes(ec[32:])
	return ecdsa.Verify(pk, hash, &r, &s)
}

// CertificationDataType is the type of data required to verify the QE Report signature in the
// QuoteSignature data structure.
type CertificationDataType uint16

const (
	CertificationDataPPIDCleartext        = 1
	CertificationDataPPIDEncryptedRSA2048 = 2
	CertificationDataPPIDEncryptedRSA3072 = 3
	CertificationDataPCKLeafCertificate   = 4
	CertificationDataPCKCertificateChain  = 5
	CertificationDataQEReport             = 6
	CertificationDataPlatformManifest     = 7
)

func (ct CertificationDataType) String() string {
	switch ct {
	case CertificationDataPPIDCleartext:
		return "PPID-cleartext"
	case CertificationDataPPIDEncryptedRSA2048:
		return "PPID-RSA2048"
	case CertificationDataPPIDEncryptedRSA3072:
		return "PPID-RSA3072"
	case CertificationDataPCKLeafCertificate:
		return "PCK-leaf"
	case CertificationDataPCKCertificateChain:
		return "PCK-chain"
	case CertificationDataQEReport:
		return "QE-report"
	case CertificationDataPlatformManifest:
		return "platform-manifest"
	default:
		return fmt.Sprintf("[unknown (%x)]", uint16(ct))
	}
}

// CertificationData is the data required to verify the QE Report signature.
type CertificationData interface {
	// CertificationDataType returns the certification data type.
	CertificationDataType() CertificationDataType
}

// CertificationData_PPID is the PPID certification data.
type CertificationData_PPID struct { // nolint: revive
	PPID   [384]byte
	CPUSVN [16]byte
	PCESVN uint16
	PCEID  uint16

	subtype CertificationDataType
}

// CertificationDataType returns the certification data type.
func (cd *CertificationData_PPID) CertificationDataType() CertificationDataType {
	return cd.subtype
}

// UnmarshalBinary decodes CertificationData_PPID from a byte array.
func (cd *CertificationData_PPID) UnmarshalBinary(data []byte) error {
	if len(data) != ppidDataLen {
		return fmt.Errorf("pcs/quote: invalid PPID certification data length")
	}

	copy(cd.PPID[:], data[0:])
	copy(cd.CPUSVN[:], data[384:])
	cd.PCESVN = binary.LittleEndian.Uint16(data[400:])
	cd.PCEID = binary.LittleEndian.Uint16(data[402:])

	return nil
}

// CertificationData_PCKCertificateChain is the PCK certificate chain certification data.
type CertificationData_PCKCertificateChain struct { // nolint: revive
	CertificateChain []*x509.Certificate
}

// CertificationDataType returns the certification data type.
func (cd *CertificationData_PCKCertificateChain) CertificationDataType() CertificationDataType {
	return CertificationDataPCKCertificateChain
}

// UnmarshalBinary decodes CertificationData_PCKCertificateChain from a byte array.
func (cd *CertificationData_PCKCertificateChain) UnmarshalBinary(data []byte) error {
	// Data should be PEM-encoded certificates.
	for len(data) > 0 {
		var (
			cert *x509.Certificate
			err  error
		)
		if cert, data, err = CertFromPEM(data); err != nil {
			return fmt.Errorf("pcs/quote: bad X509 certificate in PCK chain: %w", err)
		}
		if cert == nil {
			break
		}
		cd.CertificateChain = append(cd.CertificateChain, cert)
	}

	return nil
}
