// Package signature provides wrapper types around public key signatures.
package signature

import (
	"bytes"
	"crypto/sha512"
	"encoding"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ed25519"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/grpc/common"
)

const (
	// PublicKeySize is the size of a public key in bytes.
	PublicKeySize = ed25519.PublicKeySize

	// PrivateKeySize is the size of a private key in bytes.
	PrivateKeySize = ed25519.PrivateKeySize

	// SignatureSize is the size of a signature in bytes.
	SignatureSize = ed25519.SignatureSize

	// ContextSize is the size of a signature context in bytes
	ContextSize = 8

	pemType = "ED25519 PRIVATE KEY"
)

var (
	// ErrMalformedPublicKey is the error returned when a public key is
	// malformed.
	ErrMalformedPublicKey = errors.New("signature: malformed public key")

	// ErrMalformedSignature is the error returned when a signature is
	// malformed.
	ErrMalformedSignature = errors.New("signature: malformed signature")

	// ErrMalformedPrivateKey is the error returned when a private key is
	// malformed.
	ErrMalformedPrivateKey = errors.New("signature: malformed private key")

	// ErrPublicKeyMismatch is the error returned when a signature was
	// not produced by the expected public key.
	ErrPublicKeyMismatch = errors.New("signature: public key mismatch")

	// ErrNilProtobuf is the error returned when a protobuf is nil.
	ErrNilProtobuf = errors.New("signature: protobuf is nil")

	// ErrVerifyFailed is the error return when a signature verification
	// fails when opening a signed blob.
	ErrVerifyFailed = errors.New("signed: signature verification failed")

	errMalformedContext = errors.New("signature: malformed context")

	errNilPEM          = errors.New("signature: PEM data missing blocks")
	errTrailingGarbage = errors.New("signature: PEM data has trailing garbage")
	errMalformedPEM    = errors.New("signature: malformed PEM")

	_ cbor.Marshaler             = PublicKey{}
	_ cbor.Unmarshaler           = (*PublicKey)(nil)
	_ cbor.Marshaler             = (*Signed)(nil)
	_ cbor.Unmarshaler           = (*Signed)(nil)
	_ encoding.BinaryMarshaler   = PublicKey{}
	_ encoding.BinaryUnmarshaler = (*PublicKey)(nil)
	_ encoding.BinaryMarshaler   = RawSignature{}
	_ encoding.BinaryUnmarshaler = (*RawSignature)(nil)
	_ encoding.BinaryUnmarshaler = (*PrivateKey)(nil)
)

// MapKey is a PublicKey as a fixed sized byte array for use as a map key.
type MapKey [PublicKeySize]byte

// String returns a string representation of the MapKey.
func (k MapKey) String() string {
	return hex.EncodeToString(k[:])
}

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

// MarshalCBOR serializes the type into a CBOR byte vector.
func (k PublicKey) MarshalCBOR() []byte {
	return cbor.Marshal(k)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (k *PublicKey) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, k)
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
func (r *RawSignature) UnmarshalBinary(data []byte) error {
	if len(data) != SignatureSize {
		return ErrMalformedSignature
	}

	copy(r[:], data)

	return nil
}

// PrivateKey is a private key used for signing.
type PrivateKey ed25519.PrivateKey

// Sign generates a signature with the private key over the context and
// message.
func (k PrivateKey) Sign(context, message []byte) ([]byte, error) {
	data, err := digest(context, message)
	if err != nil {
		return nil, err
	}

	return ed25519.Sign(ed25519.PrivateKey(k), data), nil
}

// Public returns the PublicKey corresponding to k.
func (k PrivateKey) Public() PublicKey {
	return PublicKey(ed25519.PrivateKey(k).Public().(ed25519.PublicKey))
}

// String returns the string representation of a PrivateKey.
func (k PrivateKey) String() string {
	// There is close to zero reason to ever serialize a PrivateKey
	// to a string in this manner.  This method exists as a safeguard
	// against inadvertently trying to do so (eg: misguided attempts
	// at logging).
	return "[redacted private key]"
}

// UnmarshalBinary decodes a binary marshaled private key.
func (k *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return ErrMalformedPrivateKey
	}

	if len(*k) != PrivateKeySize {
		keybuf := make([]byte, PrivateKeySize)
		*k = keybuf
	}
	copy((*k)[:], data)

	return nil
}

// UnmarshalPEM decodes a PEM marshaled PrivateKey.
func (k *PrivateKey) UnmarshalPEM(data []byte) error {
	blk, rest := pem.Decode(data)
	if blk == nil {
		return errNilPEM
	}
	if len(rest) != 0 {
		return errTrailingGarbage
	}
	if blk.Type != pemType {
		return errMalformedPEM
	}

	return k.UnmarshalBinary(blk.Bytes)
}

// MarshalPEM encodes a PrivateKey into PEM form.
func (k PrivateKey) MarshalPEM() (data []byte, err error) {
	blk := &pem.Block{
		Type:  pemType,
		Bytes: k[:],
	}

	var buf bytes.Buffer
	if err = pem.Encode(&buf, blk); err != nil {
		return nil, err
	}
	data = buf.Bytes()

	return
}

// LoadPEM loads a private key from a PEM file on disk.  Iff the private
// key is missing and an entropy source is provided, a new private key
// will be generated and written.
func (k *PrivateKey) LoadPEM(fn string, rng io.Reader) error {
	const filePerm = 0600

	f, err := os.Open(fn) // nolint: gosec
	if err != nil {
		if os.IsNotExist(err) && rng != nil {
			if err = k.generate(rng); err != nil {
				return err
			}

			var buf []byte
			buf, err = k.MarshalPEM()
			if err != nil {
				return err
			}

			return ioutil.WriteFile(fn, buf, filePerm)
		}
		return err
	}
	defer f.Close() // nolint: errcheck

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	fm := fi.Mode()
	if fm.Perm() != filePerm {
		return fmt.Errorf("signature: file '%s' has invalid permissions: %v", fn, fm.Perm())
	}

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	return k.UnmarshalPEM(buf)
}

func (k *PrivateKey) generate(rng io.Reader) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rng, seed); err != nil {
		return err
	}

	nk := ed25519.NewKeyFromSeed(seed)
	_ = k.UnmarshalBinary(nk[:])

	return nil
}

// NewPrivateKey generates a new private key via the provided
// entropy source.
func NewPrivateKey(rng io.Reader) (k PrivateKey, err error) {
	err = k.generate(rng)
	return
}

// Signature is a signature, bundled with the signing public key.
type Signature struct {
	// PublicKey is the public key that produced the signature.
	PublicKey PublicKey `codec:"public_key"`

	// Signature is the actual raw signature.
	Signature RawSignature `codec:"signature"`

	// TODO: Attestation.
}

// Sign generates a signature with the private key over the context and
// message.
func Sign(privateKey PrivateKey, context, message []byte) (*Signature, error) {
	signature, err := privateKey.Sign(context, message)
	if err != nil {
		return nil, err
	}

	var rawSignature RawSignature
	if err = rawSignature.UnmarshalBinary(signature); err != nil {
		return nil, err
	}

	return &Signature{PublicKey: privateKey.Public(), Signature: rawSignature}, nil
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

// ToProto serializes a protobuf version of the Signature.
func (s *Signature) ToProto() *common.Signature {
	pb := new(common.Signature)

	pb.Pubkey, _ = s.PublicKey.MarshalBinary()
	pb.Signature, _ = s.Signature.MarshalBinary()

	return pb
}

// Signed is a signed blob.
type Signed struct {
	// Blob is the signed blob.
	Blob []byte `codec:"untrusted_raw_value"`

	// Signature is the signature over blob.
	Signature Signature `codec:"signature"`
}

// SignSigned generates a Signed with the private key over the context and
// CBOR-serialized message.
func SignSigned(privateKey PrivateKey, context []byte, src cbor.Marshaler) (*Signed, error) {
	data := src.MarshalCBOR()
	signature, err := Sign(privateKey, context, data)
	if err != nil {
		return nil, err
	}

	return &Signed{Blob: data, Signature: *signature}, nil
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *Signed) Open(context []byte, dst cbor.Unmarshaler) error {
	// Verify signature first.
	if !s.Signature.Verify(context, s.Blob) {
		return ErrVerifyFailed
	}

	return dst.UnmarshalCBOR(s.Blob)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (s *Signed) MarshalCBOR() []byte {
	return cbor.Marshal(s)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (s *Signed) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, s)
}

// FromProto deserializes a protobuf into a Signed.
func (s *Signed) FromProto(pb *common.Signed) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	s.Blob = pb.GetBlob()
	return s.Signature.FromProto(pb.GetSignature())
}

// ToProto serializes a protobuf version of the Signed.
func (s *Signed) ToProto() *common.Signed {
	return &common.Signed{
		Blob:      s.Blob,
		Signature: s.Signature.ToProto(),
	}
}

// SignedPublicKey is a signed blob containing a PublicKey.
type SignedPublicKey struct {
	Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedPublicKey) Open(context []byte, pub *PublicKey) error { // nolint: interfacer
	return s.Signed.Open(context, pub)
}

func digest(context, message []byte) ([]byte, error) {
	if len(context) != ContextSize {
		return nil, errMalformedContext
	}

	h := sha512.New512_256()
	_, _ = h.Write(context)
	_, _ = h.Write(message)
	sum := h.Sum(nil)

	return sum[:], nil
}
