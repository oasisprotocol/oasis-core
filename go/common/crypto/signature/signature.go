// Package signature provides wrapper types around public key signatures.
package signature

import (
	"bytes"
	"crypto/sha512"
	"encoding"
	"encoding/hex"
	"errors"

	"github.com/oasislabs/ekiden/go/grpc/common"

	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/ed25519"
)

const (
	// PublicKeySize is the size of a public key in bytes.
	PublicKeySize = ed25519.PublicKeySize

	// SignatureSize is the size of a signature in bytes.
	SignatureSize = ed25519.SignatureSize

	// ContextSize is the size of a signature context in bytes
	ContextSize = 8
)

var (
	// ErrMalformedPublicKey is the error returned when a public key is
	// malformed.
	ErrMalformedPublicKey = errors.New("signature: Malformed public key")

	// ErrMalformedSignature is the error returned when a signature is
	// malformed.
	ErrMalformedSignature = errors.New("signature: Malformed signature")

	// ErrPublicKeyMismatch is the error returned when a signature was
	// not produced by the expected public key.
	ErrPublicKeyMismatch = errors.New("signature: Public key mismatch")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("signature: Protobuf is nil")

	// CBORHandle is the CBOR codec Handle used to encode/decode signed
	// CBOR blobs.
	CBORHandle codec.Handle

	errMalformedContext = errors.New("signature: Malformed context")

	_ encoding.BinaryMarshaler   = PublicKey{}
	_ encoding.BinaryUnmarshaler = (*PublicKey)(nil)
	_ encoding.BinaryMarshaler   = RawSignature{}
	_ encoding.BinaryUnmarshaler = RawSignature{}
)

// MapKey is a PublicKey as a fixed sized byte array for use as a map key.
type MapKey [PublicKeySize]byte

// PublicKey is a public key used for signing.
type PublicKey ed25519.PublicKey

// Verify returns true iff the signature is valid for the public key
// over the context and message.
func (k PublicKey) Verify(context, message, sig []byte) bool {
	// XXX: Does this need to deal with attestation at all?  The
	// Rust code just returns false if it's set, so for now this
	// will totally ignore it and leave it up to the caller.

	if len(k) != PublicKeySize {
		return false
	}
	if len(sig) != SignatureSize {
		return false
	}

	data, err := digest(context, message)
	if err != nil {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(k), data, sig)
}

// MarshalBinary encodes a public key into binary form.
func (k PublicKey) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, k[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled public key.
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return ErrMalformedPublicKey
	}

	if len(*k) != PublicKeySize {
		keybuf := make([]byte, PublicKeySize)
		*k = keybuf
	}
	copy((*k)[:], data)

	return nil
}

// Equal compares vs another public key for equality.
func (k PublicKey) Equal(cmp PublicKey) bool {
	return bytes.Equal(k, cmp)
}

// String returns a string representation of the public key.
func (k PublicKey) String() string {
	hexKey := hex.EncodeToString(k)

	if len(k) != PublicKeySize {
		return "[malformed]: " + hexKey
	}

	return hexKey
}

// ToMapKey returns a fixed-sized representation of the public key.
func (k PublicKey) ToMapKey() MapKey {
	if len(k) != PublicKeySize {
		panic("signature: public key invalid size for ID")
	}

	var mk MapKey
	copy(mk[:], k)

	return mk
}

// RawSignature is a raw signature.
type RawSignature [SignatureSize]byte

// MarshalBinary encodes a signature into binary form.
func (r RawSignature) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, r[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled signature.
func (r RawSignature) UnmarshalBinary(data []byte) error {
	if len(data) != SignatureSize {
		return ErrMalformedSignature
	}

	copy(r[:], data)

	return nil
}

// Signature is a signature, bundled with the signing public key.
type Signature struct {
	// PublicKey is the public key that produced the signature.
	PublicKey PublicKey

	// Signature is the actual raw signature.
	Signature RawSignature

	// TODO: Attestation.
}

// Verify returns true iff the signature is valid over the given
// context and message.
func (s *Signature) Verify(context, message []byte) bool {
	return s.PublicKey.Verify(context, message, s.Signature[:])
}

// SanityCheck checks if the signature appears to be well formed.
func (s *Signature) SanityCheck(expectedPubKey PublicKey) error {
	if len(s.PublicKey) != PublicKeySize {
		return ErrMalformedPublicKey
	}
	if !s.PublicKey.Equal(expectedPubKey) {
		return ErrPublicKeyMismatch
	}
	if len(s.Signature) != SignatureSize {
		return ErrMalformedSignature
	}
	return nil
}

// FromProto deserializes a protobuf into a Signature.
func (s *Signature) FromProto(pb *common.Signature) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := s.PublicKey.UnmarshalBinary(pb.GetPubkey()); err != nil {
		return err
	}
	if err := s.Signature.UnmarshalBinary(pb.GetSignature()); err != nil {
		return err
	}

	// TODO: Attestation.

	return nil
}

func digest(context, message []byte) ([]byte, error) {
	if len(context) != ContextSize {
		return nil, errMalformedContext
	}

	h := sha512.New512_256()
	h.Write(context)
	h.Write(message)
	sum := h.Sum(nil)

	return sum[:], nil
}

func init() {
	h := new(codec.CborHandle)
	h.EncodeOptions.Canonical = true

	CBORHandle = h
}
