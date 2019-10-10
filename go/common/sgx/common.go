// Package SGX provides common Intel SGX datatypes and utilities.
package sgx

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
)

const (
	// MrEnclaveSize is the size of an MrEnclave in bytes.
	MrEnclaveSize = sha256.Size

	// MrSignerSize is the size of an MrSigner in bytes.
	MrSignerSize = sha256.Size

	// enclaveIdentitySize is the total size of EnclaveIdentity in bytes.
	enclaveIdentitySize = MrSignerSize + MrEnclaveSize
)

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
		return errors.New("sgx: malformed MRENCLAVE")
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
			return errors.Wrap(err, "sgx: failed to read .sgxs")
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
		return errors.New("sgx: malformed MRSIGNER")
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
	const modulusBits = 3072 // Hardware constraint.
	if pk.Size() != modulusBits/8 {
		return errors.New("sgx: invalid RSA public key for SGX signing")
	}

	// The MRSIGNER is the SHA256 digest of the little endian representation
	// of the RSA public key modulus.
	modulus := pk.N.Bytes()
	for left, right := 0, len(modulus)-1; left < right; left, right = left+1, right-1 {
		modulus[left], modulus[right] = modulus[right], modulus[left]
	}

	sum := sha256.Sum256(modulus)
	return m.UnmarshalBinary(sum[:])
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
		return errors.Wrap(err, "sgx: malformed EnclaveIdentity")
	}
	if err := id.MrEnclave.UnmarshalBinary(b[:MrEnclaveSize]); err != nil {
		return errors.Wrap(err, "sgx: malformed MrEnclave in EnclaveIdentity")
	}
	if err := id.MrSigner.UnmarshalBinary(b[MrEnclaveSize:]); err != nil {
		return errors.Wrap(err, "sgx: malformed MrSigner in EnclaveIdentity")
	}

	return nil
}

// UnmarshalHex decodes a hex marshaled EnclaveIdentity.
func (id *EnclaveIdentity) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != enclaveIdentitySize {
		return errors.Wrap(err, "sgx: malformed EnclaveIdentity")
	}

	copy(id.MrEnclave[:], b[:MrEnclaveSize])
	copy(id.MrSigner[:], b[MrEnclaveSize:])

	return nil
}

// String returns the string representation of a EnclaveIdentity.
func (id EnclaveIdentity) String() string {
	return hex.EncodeToString(id.MrEnclave[:]) + hex.EncodeToString(id.MrSigner[:])
}
