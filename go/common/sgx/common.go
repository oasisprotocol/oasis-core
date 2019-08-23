// Package SGX provides common Intel SGX datatypes and utilities.
package sgx

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
)

const (
	// MrenclaveSize is the size of an Mrenclave in bytes.
	MrenclaveSize = sha256.Size

	// MrsignerSize is the size of an Mrsigner in bytes.
	MrsignerSize = sha256.Size

	enclaveIdentitySize = MrsignerSize + MrenclaveSize
)

// Mrenclave is a SGX enclave identity register value (MRENCLAVE).
type Mrenclave [MrenclaveSize]byte

// MarshalBinary encodes a Mrenclave into binary form.
func (m *Mrenclave) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, m[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled Mrenclave.
func (m *Mrenclave) UnmarshalBinary(data []byte) error {
	if len(data) != MrenclaveSize {
		return errors.New("sgx: malformed MRENCLAVE")
	}

	copy(m[:], data)

	return nil
}

// FromSgxs derives a Mrenclave from r, under the assumption that r will
// provide the entire `.sgxs` file.
func (m *Mrenclave) FromSgxs(r io.Reader) error {
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

// FromSgxsBytes dervies a Mrenclave from a byte slice containing a `.sgxs`
// file.
func (m *Mrenclave) FromSgxsBytes(data []byte) error {
	sum := sha256.Sum256(data)
	return m.UnmarshalBinary(sum[:])
}

// String returns the string representation of a Mrenclave.
func (m Mrenclave) String() string {
	return hex.EncodeToString(m[:])
}

// Mrsigner is a SGX enclave signer register value (MRSIGNER).
type Mrsigner [MrsignerSize]byte

// MarshalBinary encodes a Mrsigner into binary form.
func (m *Mrsigner) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, m[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled Mrsigner.
func (m *Mrsigner) UnmarshalBinary(data []byte) error {
	if len(data) != MrsignerSize {
		return errors.New("sgx: malformed MRSIGNER")
	}

	copy(m[:], data)

	return nil
}

// UnmarshalHex decodes a hex marshaled Mrsigner.
func (m *Mrsigner) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return m.UnmarshalBinary(b)
}

// FromPublicKey derives a Mrsigner from a RSA public key.
func (m *Mrsigner) FromPublicKey(pk *rsa.PublicKey) error {
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

// String returns the string representation of a Mrsigner.
func (m Mrsigner) String() string {
	return hex.EncodeToString(m[:])
}

// EnclaveIdentity is a byte serialized MRSIGNER/MRENCLAVE pair.
type EnclaveIdentity [enclaveIdentitySize]byte

// MarshalBinary encodes an EnclaveIdentity into binary form.
func (id *EnclaveIdentity) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, id[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled EnclaveIdentity.
func (id *EnclaveIdentity) UnmarshalBinary(data []byte) error {
	if len(data) != enclaveIdentitySize {
		return errors.New("sgx: malformed EnclaveIdentity")
	}

	copy(id[:], data)

	return nil
}

// UnmarshalHex decodes a hex marshaled EnclaveIdentity.
func (id *EnclaveIdentity) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return errors.Wrap(err, "sgx:malformed EnclaveIdentity")
	}

	return id.UnmarshalBinary(b)
}

// FromComponents constructs an EnclaveIdentity from it's component
// parts.
func (id *EnclaveIdentity) FromComponents(mrsigner Mrsigner, mrenclave Mrenclave) {
	copy(id[0:], mrsigner[:])
	copy(id[MrsignerSize:], mrenclave[:])
}

// Mrsigner returns the MRSIGNER component of an EnclaveIdentity.
func (id *EnclaveIdentity) Mrsigner() Mrsigner {
	var ret Mrsigner
	_ = ret.UnmarshalBinary(id[:MrsignerSize])
	return ret
}

// Mrenclave returns the MRENCLAVE component of an EnclaveIdentity.
func (id *EnclaveIdentity) Mrenclave() Mrenclave {
	var ret Mrenclave
	_ = ret.UnmarshalBinary(id[MrsignerSize:])
	return ret
}

// String returns the string representation of a EnclaveIdentity.
func (id EnclaveIdentity) String() string {
	return hex.EncodeToString(id[:])
}
