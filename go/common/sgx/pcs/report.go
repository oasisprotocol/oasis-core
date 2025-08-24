package pcs

import (
	"encoding/binary"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/tuplehash"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

// ReportBody is the report body contained in the quote.
type ReportBody interface {
	// ReportData is the user-supplied report data.
	ReportData() []byte

	// AsEnclaveIdentity converts the report body into an enclave identity.
	AsEnclaveIdentity() sgx.EnclaveIdentity

	// Raw returns the raw report body.
	Raw() []byte
}

// SgxReport is an SGX enclave report body.
type SgxReport struct {
	cpuSvn     [16]byte
	miscSelect uint32
	attributes sgx.Attributes
	mrEnclave  sgx.MrEnclave
	mrSigner   sgx.MrSigner
	isvProdID  uint16
	isvSvn     uint16
	reportData [64]byte

	raw []byte
}

// MarshalBinary encodes SgxReport into byte array.
func (r *SgxReport) MarshalBinary() ([]byte, error) {
	rBin := []byte{}
	uint16b := make([]byte, 2)
	uint32b := make([]byte, 4)
	uint64b := make([]byte, 8)

	rBin = append(rBin, r.cpuSvn[:]...)
	binary.LittleEndian.PutUint32(uint32b, r.miscSelect)
	rBin = append(rBin, uint32b[:]...)
	rBin = append(rBin, make([]byte, 28)...) // 28 reserved bytes.
	binary.LittleEndian.PutUint64(uint64b, uint64(r.attributes.Flags))
	rBin = append(rBin, uint64b[:]...)
	binary.LittleEndian.PutUint64(uint64b, r.attributes.Xfrm)
	rBin = append(rBin, uint64b[:]...)
	rBin = append(rBin, r.mrEnclave[:]...)
	rBin = append(rBin, make([]byte, 32)...) // 32 reserved bytes.
	rBin = append(rBin, r.mrSigner[:]...)
	rBin = append(rBin, make([]byte, 96)...) // 96 reserved bytes.
	binary.LittleEndian.PutUint16(uint16b, r.isvProdID)
	rBin = append(rBin, uint16b[:]...)
	binary.LittleEndian.PutUint16(uint16b, r.isvSvn)
	rBin = append(rBin, uint16b[:]...)
	rBin = append(rBin, make([]byte, 60)...) // 60 reserved bytes.
	rBin = append(rBin, r.reportData[:]...)

	return rBin, nil
}

// UnmarshalBinary decodes SgxReport from a byte array.
func (r *SgxReport) UnmarshalBinary(data []byte) error {
	if len(data) < reportBodySgxLen {
		return fmt.Errorf("pcs/quote: invalid report length")
	}

	copy(r.cpuSvn[:], data[0:])
	r.miscSelect = binary.LittleEndian.Uint32(data[16:])
	r.attributes.Flags = sgx.AttributesFlags(binary.LittleEndian.Uint64(data[48:]))
	r.attributes.Xfrm = binary.LittleEndian.Uint64(data[56:])
	_ = r.mrEnclave.UnmarshalBinary(data[64 : 64+sgx.MrEnclaveSize])
	_ = r.mrSigner.UnmarshalBinary(data[128 : 128+sgx.MrSignerSize])
	r.isvProdID = binary.LittleEndian.Uint16(data[256:])
	r.isvSvn = binary.LittleEndian.Uint16(data[258:])
	copy(r.reportData[:], data[320:])

	r.raw = data[:reportBodySgxLen]

	return nil
}

// ReportData is the user-supplied report data.
func (r *SgxReport) ReportData() []byte {
	return r.reportData[:]
}

// AsEnclaveIdentity converts the report body into an enclave identity.
func (r *SgxReport) AsEnclaveIdentity() sgx.EnclaveIdentity {
	return sgx.EnclaveIdentity{
		MrEnclave: r.mrEnclave,
		MrSigner:  r.mrSigner,
	}
}

// Raw returns the raw report body.
func (r *SgxReport) Raw() []byte {
	return r.raw
}

// TdEnclaveIdentityContext is the TD enclave identity conversion context.
const TdEnclaveIdentityContext = "oasis-core/tdx: TD enclave identity"

// TdReport is a TDX TD report body.
type TdReport struct {
	teeTcbSvn      [16]byte
	mrSeam         [48]byte
	mrSignerSeam   [48]byte
	seamAttributes [8]byte
	tdAttributes   TdAttributes
	xfam           [8]byte
	mrTd           [48]byte
	mrConfigID     [48]byte
	mrOwner        [48]byte
	mrOwnerConfig  [48]byte
	rtmr0          [48]byte
	rtmr1          [48]byte
	rtmr2          [48]byte
	rtmr3          [48]byte
	reportData     [64]byte

	raw []byte
}

// UnmarshalBinary decodes TdReport from a byte array.
func (r *TdReport) UnmarshalBinary(data []byte) error {
	if len(data) < reportBodyTdLen {
		return fmt.Errorf("pcs/quote: invalid report length")
	}

	copy(r.teeTcbSvn[:], data[0:])
	copy(r.mrSeam[:], data[16:])
	copy(r.mrSignerSeam[:], data[64:])
	copy(r.seamAttributes[:], data[112:])
	if err := r.tdAttributes.UnmarshalBinary(data[120:128]); err != nil {
		return err
	}
	copy(r.xfam[:], data[128:])
	copy(r.mrTd[:], data[136:])
	copy(r.mrConfigID[:], data[184:])
	copy(r.mrOwner[:], data[232:])
	copy(r.mrOwnerConfig[:], data[280:])
	copy(r.rtmr0[:], data[328:])
	copy(r.rtmr1[:], data[376:])
	copy(r.rtmr2[:], data[424:])
	copy(r.rtmr3[:], data[472:])
	copy(r.reportData[:], data[520:])

	r.raw = data[:reportBodyTdLen]

	return nil
}

// ReportData is the user-supplied report data.
func (r *TdReport) ReportData() []byte {
	return r.reportData[:]
}

// AsEnclaveIdentity converts the report body into an enclave identity.
func (r *TdReport) AsEnclaveIdentity() sgx.EnclaveIdentity {
	var zeroMrSigner sgx.MrSigner
	// TODO: Change the EnclaveIdentity structure to allow specifying all the different things.

	// Compute MRENCLAVE as TupleHash[TD_ENCLAVE_IDENTITY_CONTEXT](MRTD, RTMR0, RTMR1, RTMR2, RTMR3).
	//
	// MRTD  -- Measurement of virtual firmware.
	// RTMR0 -- Measurement of virtual firmware data and configuration.
	// RTMR1 -- Measurement of OS loader, option ROM, boot parameters.
	// RTMR2 -- Measurement of OS kernel, initrd, boot parameters.
	// RTMR3 -- Reserved.
	//
	var mrEnclave sgx.MrEnclave
	h := tuplehash.New256(32, []byte(TdEnclaveIdentityContext))
	_, _ = h.Write(r.mrTd[:])
	_, _ = h.Write(r.rtmr0[:])
	_, _ = h.Write(r.rtmr1[:])
	_, _ = h.Write(r.rtmr2[:])
	_, _ = h.Write(r.rtmr3[:])
	rawMrEnclave := h.Sum(nil)
	copy(mrEnclave[:], rawMrEnclave[:])

	return sgx.EnclaveIdentity{
		MrEnclave: mrEnclave,
		MrSigner:  zeroMrSigner, // All-zero MRSIGNER (invalid in SGX).
	}
}

// Raw returns the raw report body.
func (r *TdReport) Raw() []byte {
	return r.raw
}

// TdAttributes are the TDX TD attributes.
type TdAttributes uint64

const (
	TdAttributeDebug         TdAttributes = 0b00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001
	TdAttributeSeptVeDisable TdAttributes = 0b00000000_00000000_00000000_00000000_00010000_00000000_00000000_00000000
	TdAttributePKS           TdAttributes = 0b00000000_00000000_00000000_00000000_01000000_00000000_00000000_00000000
	TdAttributeKL            TdAttributes = 0b00000000_00000000_00000000_00000000_10000000_00000000_00000000_00000000
	TdAttributePerfmon       TdAttributes = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000

	TdAttributeReserved TdAttributes = ^(TdAttributeDebug |
		TdAttributeSeptVeDisable |
		TdAttributePKS |
		TdAttributeKL |
		TdAttributePerfmon)
)

// UnmarshalBinary decodes TdAttributes from a byte array.
func (a *TdAttributes) UnmarshalBinary(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("pcs/quote: malformed TDX attributes in report body")
	}

	attrs := TdAttributes(binary.LittleEndian.Uint64(data[:]))
	if (uint64(attrs) & uint64(TdAttributeReserved)) != 0 {
		return fmt.Errorf("pcs/quote: malformed TDX attributes in report body")
	}

	*a = attrs
	return nil
}

// Contains returns value of given flag attribute of the Report.
func (a TdAttributes) Contains(flag TdAttributes) bool {
	return (uint64(a) & uint64(flag)) == uint64(flag)
}
