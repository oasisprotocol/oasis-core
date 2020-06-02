package ias

import (
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

const (
	// quoteLen is the length of a quote in bytes, without the signature.
	quoteLen = 432

	// quoteBodyLen is the length of the part of the quote body that comes before the report.
	quoteBodyLen = 48

	// offsetReportReportData is the offset into the report structure of the report_data field.
	offsetReportReportData = 320
)

// SignatureType is the type of signature accommpanying an enclave quote.
type SignatureType int

// Predefined enclave quote signature types.
const (
	SignatureUnlinkable SignatureType = 0
	SignatureLinkable   SignatureType = 1
)

// Body is an enclave quote body.
type Body struct {
	Version                                uint16
	SignatureType                          SignatureType
	GID                                    uint32
	ISVSVNQuotingEnclave                   uint16
	ISVSVNProvisioningCertificationEnclave uint16
	Basename                               [32]byte
}

// UnmarshalBinary decodes Body from byte array.
func (b *Body) UnmarshalBinary(data []byte) error {
	b.Version = binary.LittleEndian.Uint16(data[0:])
	switch b.Version {
	case 1, 2:
	default:
		return fmt.Errorf("ias/quote: unsupported version: %d", b.Version)
	}

	b.SignatureType = SignatureType(binary.LittleEndian.Uint16(data[2:]))
	switch b.SignatureType {
	case SignatureUnlinkable, SignatureLinkable:
	default:
		return fmt.Errorf("ias/quote: invalid signature type: %04x", b.SignatureType)
	}
	b.GID = binary.LittleEndian.Uint32(data[4:])
	b.ISVSVNQuotingEnclave = binary.LittleEndian.Uint16(data[8:])
	b.ISVSVNProvisioningCertificationEnclave = binary.LittleEndian.Uint16(data[10:])
	if b.Version < 2 && b.ISVSVNProvisioningCertificationEnclave != 0 {
		return fmt.Errorf("ias/quote: ISVSVN_PCE set for version < 2")
	}
	copy(b.Basename[:], data[16:])

	return nil
}

// MarshalBinary encodes Body to byte array.
func (b *Body) MarshalBinary() ([]byte, error) {
	bBin := []byte{}
	uint16b := make([]byte, 2)
	uint32b := make([]byte, 4)

	binary.LittleEndian.PutUint16(uint16b, b.Version)
	bBin = append(bBin, uint16b[:]...)
	binary.LittleEndian.PutUint16(uint16b, uint16(b.SignatureType))
	bBin = append(bBin, uint16b[:]...)
	binary.LittleEndian.PutUint32(uint32b, b.GID)
	bBin = append(bBin, uint32b[:]...)
	binary.LittleEndian.PutUint16(uint16b, b.ISVSVNQuotingEnclave)
	bBin = append(bBin, uint16b[:]...)
	binary.LittleEndian.PutUint16(uint16b, b.ISVSVNProvisioningCertificationEnclave)
	bBin = append(bBin, uint16b[:]...)
	bBin = append(bBin, make([]byte, 4)...) // 4 reserved bytes.
	bBin = append(bBin, b.Basename[:]...)

	return bBin, nil
}

// Report is an enclave report body.
type Report struct { // nolint: maligned
	CPUSVN     [16]byte
	MiscSelect uint32
	Attributes sgx.Attributes
	MRENCLAVE  sgx.MrEnclave
	MRSIGNER   sgx.MrSigner
	ISVProdID  uint16
	ISVSVN     uint16
	ReportData [64]byte
}

// MarshalBinary encodes Report into byte array.
func (r *Report) MarshalBinary() ([]byte, error) {
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

// UnmarshalBinary decodes Report from byte array
func (r *Report) UnmarshalBinary(data []byte) error {
	copy(r.CPUSVN[:], data[0:])
	r.MiscSelect = binary.LittleEndian.Uint32(data[16:])
	r.Attributes.Flags = sgx.AttributesFlags(binary.LittleEndian.Uint64(data[48:]))
	r.Attributes.Xfrm = binary.LittleEndian.Uint64(data[56:])
	_ = r.MRENCLAVE.UnmarshalBinary(data[64 : 64+sgx.MrEnclaveSize])
	_ = r.MRSIGNER.UnmarshalBinary(data[128 : 128+sgx.MrSignerSize])
	r.ISVProdID = binary.LittleEndian.Uint16(data[256:])
	r.ISVSVN = binary.LittleEndian.Uint16(data[258:])
	copy(r.ReportData[:], data[offsetReportReportData:])
	return nil
}

// Quote is an enclave quote.
type Quote struct {
	Body   Body
	Report Report
}

// Verify checks the quote for validity.
func (q *Quote) Verify() error {
	if mrSignerBlacklist[q.Report.MRSIGNER] {
		return fmt.Errorf("ias/quote: blacklisted MRSIGNER")
	}

	if !unsafeAllowDebugEnclaves {
		// Disallow debug enclaves, if we are in production mode.
		if q.Report.Attributes.Flags.Contains(sgx.AttributeDebug) {
			return fmt.Errorf("ias/avr: disallowed debug enclave since we are in production mode")
		}
	} else {
		// Disallow non-debug enclaves, if we are in debug mode.
		if !q.Report.Attributes.Flags.Contains(sgx.AttributeDebug) {
			return fmt.Errorf("ias/avr: disallowed production enclave since we are in debug mode")
		}
	}

	return nil
}

// MarshalBinary encodes an enclave quote.
func (q *Quote) MarshalBinary() ([]byte, error) {
	bQuote := []byte{}

	bBody, err := q.Body.MarshalBinary()
	if err != nil {
		return nil, err
	}

	bReport, err := q.Report.MarshalBinary()
	if err != nil {
		return nil, err
	}

	bQuote = append(bQuote, bBody[:]...)
	bQuote = append(bQuote, bReport[:]...)

	return bQuote, nil
}

// UnmarshalBinary decodes an enclave quote.
func (q *Quote) UnmarshalBinary(data []byte) error {
	// Signature length is variable, and also more importantly, missing
	// in the AVR.
	if len(data) < quoteLen {
		return fmt.Errorf("ias/quote: invalid quote body length")
	}
	data = data[:quoteLen] // Clip off the signature (Do we need this?).

	if err := q.Body.UnmarshalBinary(data[:quoteBodyLen]); err != nil {
		return err
	}
	if err := q.Report.UnmarshalBinary(data[quoteBodyLen:]); err != nil {
		return err
	}

	return nil
}
