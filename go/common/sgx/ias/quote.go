package ias

import (
	"encoding/binary"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/sgx"
)

const (
	// QuoteLen is the length of a quote in bytes, without the signature.
	QuoteLen = 432

	// QuoteBodyLen is the length of the part of the quote body that comes before the report.
	QuoteBodyLen = 48

	// OffsetReportReportData is the offset into the report structure of the report_data field.
	OffsetReportReportData = 320
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

func (b *Body) decode(data []byte) error {
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

// Report is an enclave report body.
type Report struct {
	CPUSVN     [16]byte
	MiscSelect uint32
	Attributes [16]byte
	MRENCLAVE  sgx.MrEnclave
	MRSIGNER   sgx.MrSigner
	ISVProdID  uint16
	ISVSVN     uint16
	ReportData [64]byte
}

func (r *Report) decode(data []byte) error {
	copy(r.CPUSVN[:], data[0:])
	r.MiscSelect = binary.LittleEndian.Uint32(data[16:])
	copy(r.Attributes[:], data[48:])
	_ = r.MRENCLAVE.UnmarshalBinary(data[64 : 64+sgx.MrEnclaveSize])
	_ = r.MRSIGNER.UnmarshalBinary(data[128 : 128+sgx.MrSignerSize])
	r.ISVProdID = binary.LittleEndian.Uint16(data[256:])
	r.ISVSVN = binary.LittleEndian.Uint16(data[258:])
	copy(r.ReportData[:], data[OffsetReportReportData:])
	return nil
}

// Quote is an enclave quote.
type Quote struct {
	Body   Body
	Report Report
}

// Verify checks the quote for validity.
func (q *Quote) Verify() error {
	if mrsignerBlacklist[q.Report.MRSIGNER] {
		return fmt.Errorf("ias/quote: blacklisted MRSIGNER")
	}
	return nil
}

// DecodeQuote decodes an enclave quote.
func DecodeQuote(data []byte) (*Quote, error) {
	// Signature length is variable, and also more importantly, missing
	// in the AVR.
	if len(data) < QuoteLen {
		return nil, fmt.Errorf("ias/quote: invalid quote body length")
	}
	data = data[:QuoteLen] // Clip off the signature (Do we need this?).

	var q Quote
	if err := q.Body.decode(data[:QuoteBodyLen]); err != nil {
		return nil, err
	}
	if err := q.Report.decode(data[QuoteBodyLen:]); err != nil {
		return nil, err
	}

	return &q, nil
}
