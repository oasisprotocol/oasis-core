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
	"math/big"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

const (
	// quoteHeaderLen is the length of the quote header in bytes.
	quoteHeaderLen = 48

	// reportBodyLen is the length of the report in bytes.
	reportBodyLen = 384

	// quoteSigSizeLen is the length of the quote signature size field in bytes.
	quoteSigSizeLen = 4

	// quoteSigEcdsaP256MinLen is the minimum length of the ECDSA-P256 quote signature in bytes.
	quoteSigEcdsaP256MinLen = 584

	// ppidDataLen is the PPID certification data length in bytes.
	ppidDataLen = 404

	// DefaultMinTCBEvaluationDataNumber is the default minimum TCB evaluation data number.
	DefaultMinTCBEvaluationDataNumber = 12 // As of 2022-08-01.
)

// QuotePolicy is the quote validity policy.
type QuotePolicy struct {
	// Disabled specifies whether PCS quotes are disabled and will always be rejected.
	Disabled bool `json:"disabled,omitempty"`

	// TCBValidityPeriod is the validity (in days) of the TCB collateral.
	TCBValidityPeriod uint16 `json:"tcb_validity_period"`

	// MinTCBEvaluationDataNumber is the minimum TCB evaluation data number that is considered to be
	// valid. TCB bundles containing smaller values will be invalid.
	MinTCBEvaluationDataNumber uint32 `json:"min_tcb_evaluation_data_number"`
}

// Quote is an enclave quote.
type Quote struct {
	Header    QuoteHeader
	ISVReport ReportBody
	Signature QuoteSignature
}

// UnmarshalBinary decodes a Quote from a byte array.
func (q *Quote) UnmarshalBinary(data []byte) error {
	if len(data) < quoteHeaderLen+reportBodyLen+quoteSigSizeLen {
		return fmt.Errorf("pcs/quote: invalid quote length")
	}

	// Quote Header.
	var offset int
	if err := q.Header.UnmarshalBinary(data[offset : offset+quoteHeaderLen]); err != nil {
		return err
	}
	offset += quoteHeaderLen

	// ISV Report.
	if err := q.ISVReport.UnmarshalBinary(data[offset : offset+reportBodyLen]); err != nil {
		return err
	}
	offset += reportBodyLen

	// Quote Signature Length.
	sigLen := int(binary.LittleEndian.Uint32(data[offset:]))
	offset += quoteSigSizeLen
	if len(data) != quoteHeaderLen+reportBodyLen+quoteSigSizeLen+sigLen {
		return fmt.Errorf("pcs/quote: unexpected trailing data")
	}

	// Quote Signature.
	switch q.Header.attestationKeyType {
	case AttestationKeyECDSA_P256:
		var qs QuoteSignatureECDSA_P256
		if err := qs.UnmarshalBinary(data[offset : offset+sigLen]); err != nil {
			return err
		}
		q.Signature = &qs
	default:
		return fmt.Errorf("pcs/quote: unsupported attestation key type: %s", q.Header.attestationKeyType)
	}

	return nil
}

// Verify verifies the quote.
//
// In case of successful verification it returns the TCB level.
func (q *Quote) Verify(policy *QuotePolicy, ts time.Time, tcb *TCBBundle) (*sgx.VerifiedQuote, error) {
	if !bytes.Equal(q.Header.QEVendorID[:], QEVendorID_Intel) {
		return nil, fmt.Errorf("pcs/quote: unsupported QE vendor: %X", q.Header.QEVendorID)
	}

	if mrSignerBlacklist[q.ISVReport.MRSIGNER] {
		return nil, fmt.Errorf("pcs/quote: blacklisted MRSIGNER")
	}

	isDebug := q.ISVReport.Attributes.Flags.Contains(sgx.AttributeDebug)
	if unsafeAllowDebugEnclaves != isDebug {
		// Debug enclaves are only allowed in debug mode, prod enclaves in prod mode.
		// A mismatch is an error.
		return nil, fmt.Errorf("pcs/quote: disallowed debug/production enclave/mode combination")
	}

	if policy == nil {
		policy = &QuotePolicy{
			TCBValidityPeriod:          30,
			MinTCBEvaluationDataNumber: DefaultMinTCBEvaluationDataNumber,
		}
	}

	if policy.Disabled {
		return nil, fmt.Errorf("pcs/quote: PCS quotes are disabled by policy")
	}

	err := q.Signature.Verify(&q.Header, &q.ISVReport, ts, tcb, policy)
	if err != nil {
		return nil, err
	}

	return &sgx.VerifiedQuote{
		ReportData: q.ISVReport.ReportData[:],
		Identity: sgx.EnclaveIdentity{
			MrEnclave: q.ISVReport.MRENCLAVE,
			MrSigner:  q.ISVReport.MRSIGNER,
		},
	}, nil
}

// QuoteHeader is a quote header.
type QuoteHeader struct {
	Version    uint16
	QESVN      uint16
	PCESVN     uint16
	QEVendorID [16]byte
	UserData   [20]byte

	attestationKeyType AttestationKeyType
	raw                []byte
}

// UnmarshalBinary decodes QuoteHeader from a byte array.
func (qh *QuoteHeader) UnmarshalBinary(data []byte) error {
	if len(data) != quoteHeaderLen {
		return fmt.Errorf("pcs/quote: invalid quote header length")
	}

	qh.Version = binary.LittleEndian.Uint16(data[0:])
	if qh.Version != 3 {
		return fmt.Errorf("pcs/quote: unsupported quote version %d", qh.Version)
	}

	qh.attestationKeyType = AttestationKeyType(binary.LittleEndian.Uint16(data[2:]))
	qh.QESVN = binary.LittleEndian.Uint16(data[8:])
	qh.PCESVN = binary.LittleEndian.Uint16(data[10:])
	copy(qh.QEVendorID[:], data[12:])
	copy(qh.UserData[:], data[28:])

	qh.raw = data[:quoteHeaderLen]

	return nil
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
		header *QuoteHeader,
		isvReport *ReportBody,
		ts time.Time,
		tcb *TCBBundle,
		policy *QuotePolicy,
	) error
}

// QuoteSignatureECDSA_P256 is an ECDSA-P256 quote signature.
type QuoteSignatureECDSA_P256 struct { // nolint: revive
	Signature            SignatureECDSA_P256
	AttestationPublicKey [64]byte
	QEReport             ReportBody
	QESignature          SignatureECDSA_P256
	AuthenticationData   []byte
	CertificationData    CertificationData
}

// AttestationKeyType returns the type of the attestation key used in this quote signature.
func (qs *QuoteSignatureECDSA_P256) AttestationKeyType() AttestationKeyType {
	return AttestationKeyECDSA_P256
}

// UnmarshalBinary decodes QuoteSignatureECDSA_P256 from a byte array.
func (qs *QuoteSignatureECDSA_P256) UnmarshalBinary(data []byte) error {
	if len(data) < quoteSigEcdsaP256MinLen {
		return fmt.Errorf("pcs/quote: invalid ECDSA-P256 quote signature length")
	}

	var offset int
	copy(qs.Signature[:], data[0:])
	offset += len(qs.Signature)

	copy(qs.AttestationPublicKey[:], data[offset:])
	offset += len(qs.AttestationPublicKey)

	if err := qs.QEReport.UnmarshalBinary(data[offset : offset+reportBodyLen]); err != nil {
		return err
	}
	offset += reportBodyLen

	copy(qs.QESignature[:], data[offset:])
	offset += len(qs.QESignature)

	authDataSize := int(binary.LittleEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < authDataSize+quoteSigEcdsaP256MinLen {
		return fmt.Errorf("pcs/quote: invalid ECDSA-P256 quote signature authentication data size")
	}
	qs.AuthenticationData = make([]byte, authDataSize)
	copy(qs.AuthenticationData[:], data[offset:offset+authDataSize])
	offset += authDataSize

	certificationDataType := CertificationDataType(binary.LittleEndian.Uint16(data[offset:]))
	certDataSize := int(binary.LittleEndian.Uint32(data[offset+2:]))
	if len(data) < certDataSize+authDataSize+quoteSigEcdsaP256MinLen {
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
		qs.CertificationData = &cd
	case CertificationDataPCKCertificateChain:
		var cd CertificationData_PCKCertificateChain
		if err := cd.UnmarshalBinary(certData); err != nil {
			return err
		}
		qs.CertificationData = &cd
	default:
		return fmt.Errorf("pcs/quote: unsupported certification data type: %s", certificationDataType)
	}

	return nil
}

func (qs *QuoteSignatureECDSA_P256) verifyCertificateChain(ts time.Time) (*x509.Certificate, error) {
	cd, ok := qs.CertificationData.(*CertificationData_PCKCertificateChain)
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
	PCESVN     int32
	CPUSVN     [16]byte
}

// VerifyPCK verifies the PCK certificate and returns the extracted information.
func (qs *QuoteSignatureECDSA_P256) VerifyPCK(ts time.Time) (*PCKInfo, error) {
	// Verify PCK certificate chain.
	leafCert, err := qs.verifyCertificateChain(ts)
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
						if _, err = asn1.Unmarshal(tcbExt.Value.FullBytes, &pckInfo.PCESVN); err != nil {
							return nil, fmt.Errorf("pcs/quote: bad PCESVN: %w", err)
						}
					case compId == 18:
						// CPUSVN
						cpusvnSlice := pckInfo.CPUSVN[:]
						if _, err = asn1.Unmarshal(tcbExt.Value.FullBytes, &cpusvnSlice); err != nil {
							return nil, fmt.Errorf("pcs/quote: bad CPUSVN: %w", err)
						}
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

// Verify verifies the quote signature.
func (qs *QuoteSignatureECDSA_P256) Verify(
	header *QuoteHeader,
	isvReport *ReportBody,
	ts time.Time,
	tcb *TCBBundle,
	policy *QuotePolicy,
) error {
	// Verify PCK certificate chain and extract relevant information (e.g. public key and FMSPC).
	pckInfo, err := qs.VerifyPCK(ts)
	if err != nil {
		return err
	}

	// Verify QE report signature using PCK public key.
	reportHash := sha256.Sum256(qs.QEReport.raw)
	if !qs.QESignature.Verify(pckInfo.PublicKey, reportHash[:]) {
		return fmt.Errorf("pcs/quote: failed to verify QE report signature using PCK public key")
	}

	// Verify QE report data. First 32 bytes MUST be:
	//   SHA-256(AttestationPublicKey || AuthenticationData)
	// and the remaining 32 bytes MUST be zero.
	h := sha256.New()
	h.Write(qs.AttestationPublicKey[:])
	h.Write(qs.AuthenticationData[:])
	expectedHash := h.Sum(nil)

	if !bytes.Equal(qs.QEReport.ReportData[:32], expectedHash) {
		return fmt.Errorf("pcs/quote: QE report data does not match expected value")
	}
	var allZeros [32]byte
	if !bytes.Equal(qs.QEReport.ReportData[32:], allZeros[:]) {
		return fmt.Errorf("pcs/quote: QE report data does not match expected value")
	}

	// Verify TCB and QE identity.
	if tcb == nil {
		return fmt.Errorf("pcs/quote: missing TCB bundle")
	}
	err = tcb.VerifyTCBLevel(ts, policy, pckInfo.FMSPC, pckInfo.TCBCompSVN, pckInfo.PCESVN, &qs.QEReport)
	if err != nil {
		return fmt.Errorf("pcs/quote: failed to get TCB level: %w", err)
	}

	// Verify quote header and ISV report body signature.
	attPkWithTag := append([]byte{0x04}, qs.AttestationPublicKey[:]...) // Add SEC 1 tag (uncompressed).
	x, y := elliptic.Unmarshal(elliptic.P256(), attPkWithTag)
	if x == nil {
		return fmt.Errorf("pcs/quote: invalid attestation public key")
	}
	attPk := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	h.Reset()
	h.Write(header.raw)
	h.Write(isvReport.raw)
	expectedHash = h.Sum(nil)

	if !qs.Signature.Verify(&attPk, expectedHash) {
		return fmt.Errorf("pcs/quote: failed to verify quote signature")
	}

	return nil
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

// ReportBody is an enclave report body.
type ReportBody struct { // nolint: maligned
	CPUSVN     [16]byte
	MiscSelect uint32
	Attributes sgx.Attributes
	MRENCLAVE  sgx.MrEnclave
	MRSIGNER   sgx.MrSigner
	ISVProdID  uint16
	ISVSVN     uint16
	ReportData [64]byte

	raw []byte
}

// MarshalBinary encodes ReportBody into byte array.
func (r *ReportBody) MarshalBinary() ([]byte, error) {
	rBin := []byte{}
	uint16b := make([]byte, 2)
	uint32b := make([]byte, 4)
	uint64b := make([]byte, 8)

	rBin = append(rBin, r.CPUSVN[:]...)
	binary.LittleEndian.PutUint32(uint32b, r.MiscSelect)
	rBin = append(rBin, uint32b[:]...)
	rBin = append(rBin, make([]byte, 28)...) // 28 reserved bytes.
	binary.LittleEndian.PutUint64(uint64b, uint64(r.Attributes.Flags))
	rBin = append(rBin, uint64b[:]...)
	binary.LittleEndian.PutUint64(uint64b, r.Attributes.Xfrm)
	rBin = append(rBin, uint64b[:]...)
	rBin = append(rBin, r.MRENCLAVE[:]...)
	rBin = append(rBin, make([]byte, 32)...) // 32 reserved bytes.
	rBin = append(rBin, r.MRSIGNER[:]...)
	rBin = append(rBin, make([]byte, 96)...) // 96 reserved bytes.
	binary.LittleEndian.PutUint16(uint16b, r.ISVProdID)
	rBin = append(rBin, uint16b[:]...)
	binary.LittleEndian.PutUint16(uint16b, r.ISVSVN)
	rBin = append(rBin, uint16b[:]...)
	rBin = append(rBin, make([]byte, 60)...) // 60 reserved bytes.
	rBin = append(rBin, r.ReportData[:]...)

	return rBin, nil
}

// UnmarshalBinary decodes ReportBody from a byte array.
func (r *ReportBody) UnmarshalBinary(data []byte) error {
	if len(data) < reportBodyLen {
		return fmt.Errorf("pcs/quote: invalid report length")
	}

	copy(r.CPUSVN[:], data[0:])
	r.MiscSelect = binary.LittleEndian.Uint32(data[16:])
	r.Attributes.Flags = sgx.AttributesFlags(binary.LittleEndian.Uint64(data[48:]))
	r.Attributes.Xfrm = binary.LittleEndian.Uint64(data[56:])
	_ = r.MRENCLAVE.UnmarshalBinary(data[64 : 64+sgx.MrEnclaveSize])
	_ = r.MRSIGNER.UnmarshalBinary(data[128 : 128+sgx.MrSignerSize])
	r.ISVProdID = binary.LittleEndian.Uint16(data[256:])
	r.ISVSVN = binary.LittleEndian.Uint16(data[258:])
	copy(r.ReportData[:], data[320:])

	r.raw = data[:reportBodyLen]

	return nil
}
