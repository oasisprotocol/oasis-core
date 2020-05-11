// Package SGX provides common Intel SGX datatypes and utilities.
package sgx

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

const (
	// MrEnclaveSize is the size of an MrEnclave in bytes.
	MrEnclaveSize = sha256.Size

	// MrSignerSize is the size of an MrSigner in bytes.
	MrSignerSize = sha256.Size

	// enclaveIdentitySize is the total size of EnclaveIdentity in bytes.
	enclaveIdentitySize = MrSignerSize + MrEnclaveSize

	// ModulusSize is the required RSA modulus size in bits.
	ModulusSize = 3072

	modulusBytes = ModulusSize / 8
)

// AttributesFlags is attributes flags inside enclave report attributes.
type AttributesFlags uint64

// Predefined enclave report attributes flags.
const (
	AttributeInit          AttributesFlags = 0b0000_0001
	AttributeDebug         AttributesFlags = 0b0000_0010
	AttributeMode64Bit     AttributesFlags = 0b0000_0100
	AttributeProvisionKey  AttributesFlags = 0b0001_0000
	AttributeEInitTokenKey AttributesFlags = 0b0010_0000
)

// Attributes is a SGX enclave attributes value inside report.
type Attributes struct {
	Flags AttributesFlags
	Xfrm  uint64
}

// GetFlagInit returns value of given flag attribute of the Report.
func (a AttributesFlags) Contains(flag AttributesFlags) bool {
	return (uint64(a) & uint64(flag)) != 0
}

// Mrenclave is a SGX enclave identity register value (MRENCLAVE).
type MrEnclave [MrEnclaveSize]byte

// MarshalBinary encodes a Mrenclave into binary form.
func (m *MrEnclave) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, m[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled Mrenclave.
func (m *MrEnclave) UnmarshalBinary(data []byte) error {
	if len(data) != MrEnclaveSize {
		return fmt.Errorf("sgx: malformed MRENCLAVE")
	}

	copy(m[:], data)

	return nil
}

// UnmarshalHex decodes a hex marshaled MrEnclave.
func (m *MrEnclave) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return m.UnmarshalBinary(b)
}

// FromSgxs derives a MrEnclave from r, under the assumption that r will
// provide the entire `.sgxs` file.
func (m *MrEnclave) FromSgxs(r io.Reader) error {
	// A `.sgxs` file's SHA256 digest is conveniently the MRENCLAVE.
	var buf [32768]byte

	h := sha256.New()
readLoop:
	for {
		l, err := r.Read(buf[:])
		if l > 0 {
			_, _ = h.Write(buf[:l])
		}
		switch err {
		case nil:
		case io.EOF:
			break readLoop
		default:
			return fmt.Errorf("sgx: failed to read .sgxs: %w", err)
		}
	}

	sum := h.Sum(nil)
	return m.UnmarshalBinary(sum)
}

// FromSgxsBytes dervies a MrEnclave from a byte slice containing a `.sgxs`
// file.
func (m *MrEnclave) FromSgxsBytes(data []byte) error {
	sum := sha256.Sum256(data)
	return m.UnmarshalBinary(sum[:])
}

// String returns the string representation of a MrEnclave.
func (m MrEnclave) String() string {
	return hex.EncodeToString(m[:])
}

// MrSigner is a SGX enclave signer register value (MRSIGNER).
type MrSigner [MrSignerSize]byte

// MarshalBinary encodes a MrSigner into binary form.
func (m *MrSigner) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, m[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled MrSigner.
func (m *MrSigner) UnmarshalBinary(data []byte) error {
	if len(data) != MrSignerSize {
		return fmt.Errorf("sgx: malformed MRSIGNER")
	}

	copy(m[:], data)

	return nil
}

// UnmarshalHex decodes a hex marshaled MrSigner.
func (m *MrSigner) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return m.UnmarshalBinary(b)
}

// FromPublicKey derives a MrSigner from a RSA public key.
func (m *MrSigner) FromPublicKey(pk *rsa.PublicKey) error {
	// The MRSIGNER is the SHA256 digest of the little endian representation
	// of the RSA public key modulus.
	modulus, err := To3072le(pk.N, false)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(modulus)
	return m.UnmarshalBinary(sum[:])
}

// To3072le converts a big.Int to a 3072 bit little endian representation,
// padding if allowed AND required.
func To3072le(z *big.Int, mayPad bool) ([]byte, error) {
	buf := z.Bytes()

	sz := len(buf)
	if sz != modulusBytes {
		padLen := modulusBytes - sz
		if !mayPad || padLen < 0 {
			return nil, fmt.Errorf("sgx: big int is not %v bits: %v", ModulusSize, sz)
		}

		// Pad before reversing.
		padded := make([]byte, padLen, modulusBytes)
		buf = append(padded, buf...)
	}

	buf = reverseBuffer(buf)

	return buf, nil
}

// From3072le converts a 3072 bit buffer to the corresponding big.Int, assuming
// that the buffer is in little endian representation.
func From3072le(b []byte) (*big.Int, error) {
	if sz := len(b); sz != modulusBytes {
		return nil, fmt.Errorf("sgx: buffer is not %v bits: %v", modulusBytes, sz)
	}

	buf := reverseBuffer(b)
	var ret big.Int
	return ret.SetBytes(buf), nil
}

func reverseBuffer(b []byte) []byte {
	buf := append([]byte{}, b...)
	for left, right := 0, len(buf)-1; left < right; left, right = left+1, right-1 {
		buf[left], buf[right] = buf[right], buf[left]
	}
	return buf
}

// String returns the string representation of a MrSigner.
func (m MrSigner) String() string {
	return hex.EncodeToString(m[:])
}

// EnclaveIdentity is a byte serialized MRSIGNER/MRENCLAVE pair.
type EnclaveIdentity struct {
	MrEnclave MrEnclave `json:"mr_enclave"`
	MrSigner  MrSigner  `json:"mr_signer"`
}

// MarshalText encodes an EnclaveIdentity into text form.
func (id EnclaveIdentity) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(append(id.MrEnclave[:], id.MrSigner[:]...))), nil
}

// UnmarshalText decodes a text marshaled EnclaveIdentity.
func (id *EnclaveIdentity) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("sgx: malformed EnclaveIdentity: %w", err)
	}
	if err := id.MrEnclave.UnmarshalBinary(b[:MrEnclaveSize]); err != nil {
		return fmt.Errorf("sgx: malformed MrEnclave in EnclaveIdentity: %w", err)
	}
	if err := id.MrSigner.UnmarshalBinary(b[MrEnclaveSize:]); err != nil {
		return fmt.Errorf("sgx: malformed MrSigner in EnclaveIdentity: %w", err)
	}

	return nil
}

// UnmarshalHex decodes a hex marshaled EnclaveIdentity.
func (id *EnclaveIdentity) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != enclaveIdentitySize {
		return fmt.Errorf("sgx: malformed EnclaveIdentity: %w", err)
	}

	copy(id.MrEnclave[:], b[:MrEnclaveSize])
	copy(id.MrSigner[:], b[MrEnclaveSize:])

	return nil
}

// String returns the string representation of a EnclaveIdentity.
func (id EnclaveIdentity) String() string {
	return hex.EncodeToString(id.MrEnclave[:]) + hex.EncodeToString(id.MrSigner[:])
}
