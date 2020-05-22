// Package signature provides wrapper types around public key signatures.
package signature

import (
	"bytes"
	"crypto/rand"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	encPem "encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sync"

	"github.com/oasislabs/ed25519"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/pem"
	"github.com/oasislabs/oasis-core/go/common/prettyprint"
)

const (
	// PublicKeySize is the size of a public key in bytes.
	PublicKeySize = ed25519.PublicKeySize

	// SignatureSize is the size of a signature in bytes.
	SignatureSize = ed25519.SignatureSize

	pubPEMType = "ED25519 PUBLIC KEY"
	sigPEMType = "ED25519 SIGNATURE"
	filePerm   = 0600
)

var (
	// ErrMalformedPublicKey is the error returned when a public key is
	// malformed.
	ErrMalformedPublicKey = errors.New("signature: malformed public key")

	// ErrMalformedSignature is the error returned when a signature is
	// malformed.
	ErrMalformedSignature = errors.New("signature: malformed signature")

	// ErrPublicKeyMismatch is the error returned when a signature was
	// not produced by the expected public key.
	ErrPublicKeyMismatch = errors.New("signature: public key mismatch")

	// ErrVerifyFailed is the error return when a signature verification
	// fails when opening a signed blob.
	ErrVerifyFailed = errors.New("signed: signature verification failed")

	errKeyMismatch = errors.New("signature: public key PEM is not for private key")

	_ encoding.BinaryMarshaler   = PublicKey{}
	_ encoding.BinaryUnmarshaler = (*PublicKey)(nil)
	_ encoding.BinaryMarshaler   = RawSignature{}
	_ encoding.BinaryUnmarshaler = (*RawSignature)(nil)
	_ prettyprint.PrettyPrinter  = (*PrettySigned)(nil)
	_ prettyprint.PrettyPrinter  = (*PrettyMultiSigned)(nil)

	testPublicKeys        sync.Map
	blacklistedPublicKeys sync.Map

	defaultOptions = &ed25519.Options{}
)

// PublicKey is a public key used for signing.
type PublicKey [PublicKeySize]byte

// Verify returns true iff the signature is valid for the public key
// over the context and message.
func (k PublicKey) Verify(context Context, message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	if k.isBlacklisted() {
		return false
	}

	data, err := PrepareSignerMessage(context, message)
	if err != nil {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(k[:]), data, sig)
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

	copy(k[:], data)

	return nil
}

// UnmarshalPEM decodes a PEM marshaled PublicKey.
func (k *PublicKey) UnmarshalPEM(data []byte) error {
	b, err := pem.Unmarshal(pubPEMType, data)
	if err != nil {
		return err
	}

	return k.UnmarshalBinary(b)
}

// MarshalPEM encodes a PublicKey into PEM form.
func (k PublicKey) MarshalPEM() (data []byte, err error) {
	return pem.Marshal(pubPEMType, k[:])
}

// MarshalText encodes a public key into text form.
func (k PublicKey) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(k[:])), nil
}

// UnmarshalText decodes a text marshaled public key.
func (k *PublicKey) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return k.UnmarshalBinary(b)
}

// UnmarshalHex deserializes a hexadecimal text string into the given type.
func (k *PublicKey) UnmarshalHex(text string) error {
	b, err := hex.DecodeString(text)
	if err != nil {
		return err
	}

	return k.UnmarshalBinary(b)
}

// Equal compares vs another public key for equality.
func (k PublicKey) Equal(cmp PublicKey) bool {
	return bytes.Equal(k[:], cmp[:])
}

// String returns a string representation of the public key.
func (k PublicKey) String() string {
	b64Key := base64.StdEncoding.EncodeToString(k[:])

	if len(k) != PublicKeySize {
		return "[malformed]: " + b64Key
	}

	return b64Key
}

// IsValid checks whether the public key is well-formed.
func (k PublicKey) IsValid() bool {
	if len(k) != PublicKeySize {
		return false
	}
	if k.isBlacklisted() {
		return false
	}
	return true
}

// LoadPEM loads a public key from a PEM file on disk.  Iff the public key
// is missing and a Signer is provided, the Signer's corresponding
// public key will be written and loaded.
func (k *PublicKey) LoadPEM(fn string, signer Signer) error {
	f, err := os.Open(fn) // nolint: gosec
	if err != nil {
		if os.IsNotExist(err) && signer != nil {
			pubKey := signer.Public()

			var buf []byte
			if buf, err = pubKey.MarshalPEM(); err != nil {
				return err
			}

			copy((*k)[:], pubKey[:])

			return ioutil.WriteFile(fn, buf, filePerm)
		}
		return err
	}
	defer f.Close() // nolint: errcheck

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	if err = k.UnmarshalPEM(buf); err != nil {
		return err
	}

	if signer != nil && !k.Equal(signer.Public()) {
		return errKeyMismatch
	}

	return nil
}

// Hash returns a cryptographic hash of the public key.
func (k PublicKey) Hash() hash.Hash {
	return hash.NewFromBytes(k[:])
}

func (k PublicKey) isBlacklisted() bool {
	_, isBlacklisted := blacklistedPublicKeys.Load(k)
	return isBlacklisted
}

// RawSignature is a raw signature.
type RawSignature [SignatureSize]byte

// String returns a string representation of the raw signature.
func (r RawSignature) String() string {
	data, _ := r.MarshalText()
	return string(data)
}

// Equal compares vs another public key for equality.
func (r RawSignature) Equal(cmp RawSignature) bool {
	return bytes.Equal(r[:], cmp[:])
}

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

// MarshalText encodes a signature into text form.
func (r RawSignature) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(r[:])), nil
}

// UnmarshalText decodes a text marshaled signature.
func (r *RawSignature) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return r.UnmarshalBinary(b)
}

// MarshalPEM encodes a raw signature into PEM format.
func (r RawSignature) MarshalPEM() (data []byte, err error) {
	return pem.Marshal(sigPEMType, r[:])
}

// UnmarshalPEM decodes a PEM marshaled raw signature.
func (r *RawSignature) UnmarshalPEM(data []byte) error {
	sig, err := pem.Unmarshal(sigPEMType, data)
	if err != nil {
		return err
	}
	copy(r[:], sig)

	return nil
}

// Signature is a signature, bundled with the signing public key.
type Signature struct {
	// PublicKey is the public key that produced the signature.
	PublicKey PublicKey `json:"public_key"`

	// Signature is the actual raw signature.
	Signature RawSignature `json:"signature"`
}

// Equal compares vs another signature for equality.
func (s *Signature) Equal(cmp *Signature) bool {
	if !s.PublicKey.Equal(cmp.PublicKey) {
		return false
	}
	if !s.Signature.Equal(cmp.Signature) {
		return false
	}
	return true
}

// Sign generates a signature with the private key over the context and
// message.
func Sign(signer Signer, context Context, message []byte) (*Signature, error) {
	signature, err := signer.ContextSign(context, message)
	if err != nil {
		return nil, err
	}

	var rawSignature RawSignature
	if err = rawSignature.UnmarshalBinary(signature); err != nil {
		return nil, err
	}

	return &Signature{PublicKey: signer.Public(), Signature: rawSignature}, nil
}

// Verify returns true iff the signature is valid over the given
// context and message.
func (s *Signature) Verify(context Context, message []byte) bool {
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

// MarshalPEM encodes a signature into PEM format.
func (s Signature) MarshalPEM() (data []byte, err error) {
	pk, err := s.PublicKey.MarshalPEM()
	if err != nil {
		return []byte{}, err
	}

	sig, err := s.Signature.MarshalPEM()
	if err != nil {
		return []byte{}, err
	}

	return bytes.Join([][]byte{pk, sig}, []byte{}), nil
}

// UnmarshalPem decodes a PEM marshaled signature.
func (s *Signature) UnmarshalPEM(data []byte) error {
	// Marshalled PEM file contains public key block first...
	blk, rest := encPem.Decode(data)
	if blk == nil {
		return fmt.Errorf("signature: error while decoding PEM block %s", pubPEMType)
	}

	if blk.Type != pubPEMType {
		return fmt.Errorf("signature: expected different PEM block (expected: %s got: %s)", pubPEMType, blk.Type)
	}
	if err := s.PublicKey.UnmarshalBinary(blk.Bytes); err != nil {
		return err
	}

	// ...and then raw signature.
	blk, _ = encPem.Decode(rest)
	if blk == nil {
		return fmt.Errorf("signature: error while decoding PEM block %s", sigPEMType)
	}

	if blk.Type != sigPEMType {
		return fmt.Errorf("signature: expected different PEM block (expected: %s got: %s)", sigPEMType, blk.Type)
	}
	if err := s.Signature.UnmarshalBinary(blk.Bytes); err != nil {
		return err
	}

	return nil
}

// Signed is a signed blob.
type Signed struct {
	// Blob is the signed blob.
	Blob []byte `json:"untrusted_raw_value"`

	// Signature is the signature over blob.
	Signature Signature `json:"signature"`
}

// SignSigned generates a Signed with the Signer over the context and
// CBOR-serialized message.
func SignSigned(signer Signer, context Context, src interface{}) (*Signed, error) {
	data := cbor.Marshal(src)
	signature, err := Sign(signer, context, data)
	if err != nil {
		return nil, err
	}

	return &Signed{Blob: data, Signature: *signature}, nil
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *Signed) Open(context Context, dst interface{}) error {
	// Verify signature first.
	if !s.Signature.Verify(context, s.Blob) {
		return ErrVerifyFailed
	}

	return cbor.Unmarshal(s.Blob, dst)
}

// PrettySigned is used for pretty-printing signed messages so that
// the actual content is displayed instead of the binary blob.
//
// It should only be used for pretty printing.
type PrettySigned struct {
	Body      interface{} `json:"untrusted_raw_value"`
	Signature Signature   `json:"signature"`
}

// PrettyPrint writes a pretty-printed representation of the type
// to the given writer.
func (p PrettySigned) PrettyPrint(prefix string, w io.Writer) {
	data, err := json.MarshalIndent(p, prefix, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
	}
	fmt.Fprintf(w, "%s%s\n", prefix, data)
}

// NewPrettySigned creates a new PrettySigned instance that can be
// used for pretty printing signed values.
func NewPrettySigned(s Signed, b interface{}) *PrettySigned {
	return &PrettySigned{
		Body:      b,
		Signature: s.Signature,
	}
}

// MultiSigned is a blob signed by multiple public keys.
type MultiSigned struct {
	// Blob is the signed blob.
	Blob []byte `json:"untrusted_raw_value"`

	// Signatures are the signatures over the blob.
	Signatures []Signature `json:"signatures"`
}

// Open first verifies the blob signatures, and then unmarshals the blob.
func (s *MultiSigned) Open(context Context, dst interface{}) error {
	if !VerifyManyToOne(context, s.Blob, s.Signatures) {
		return ErrVerifyFailed
	}

	return cbor.Unmarshal(s.Blob, dst)
}

// IsSignedBy returns true iff the MultiSigned includes a signature for
// the provided public key.
//
// Note: This does not verify the signature.
func (s *MultiSigned) IsSignedBy(pk PublicKey) bool {
	for _, v := range s.Signatures {
		if v.PublicKey.Equal(pk) {
			return true
		}
	}

	return false
}

// IsOnlySignedBy returns true iff the MultiSigned is signed by all of
// the provided public keys, and none other.
//
// Note: This does not verify the signature, and including the same key
// more than once in pks will always return false.
func (s *MultiSigned) IsOnlySignedBy(pks []PublicKey) bool {
	m := make(map[PublicKey]bool)
	for _, v := range s.Signatures {
		m[v.PublicKey] = true
	}

	// The one consumer of this expects all of the signing keys to be
	// distinct, so trivially enforce that invariant here.
	if len(m) != len(pks) {
		return false
	}

	for _, v := range pks {
		if !m[v] {
			return false
		}
	}

	return true
}

// SignMultiSigned generates a MultiSigned with the Signers over the context
// and CBOR-serialized message.
func SignMultiSigned(signers []Signer, context Context, src interface{}) (*MultiSigned, error) {
	ms := &MultiSigned{
		Blob: cbor.Marshal(src),
	}

	for _, v := range signers {
		sig, err := Sign(v, context, ms.Blob)
		if err != nil {
			return nil, err
		}
		ms.Signatures = append(ms.Signatures, *sig)
	}

	return ms, nil
}

// PrettyMultiSigned is used for pretty-printing multi-signed messages
// so that the actual content is displayed instead of the binary blob.
//
// It should only be used for pretty printing.
type PrettyMultiSigned struct {
	Body       interface{} `json:"untrusted_raw_value"`
	Signatures []Signature `json:"signatures"`
}

// PrettyPrint writes a pretty-printed representation of the type to the
// given writer.
func (p PrettyMultiSigned) PrettyPrint(prefix string, w io.Writer) {
	data, err := json.MarshalIndent(p, prefix, "  ")
	if err != nil {
		fmt.Fprintf(w, "%s<error: %s>\n", prefix, err)
	}
	fmt.Fprintf(w, "%s%s\n", prefix, data)
}

// NewPrettyMultiSigned creates a new PrettySigned instance that can be
// used for pretty printing multi-signed values.
func NewPrettyMultiSigned(s MultiSigned, b interface{}) *PrettyMultiSigned {
	return &PrettyMultiSigned{
		Body:       b,
		Signatures: s.Signatures,
	}
}

// SignedPublicKey is a signed blob containing a PublicKey.
type SignedPublicKey struct {
	Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedPublicKey) Open(context Context, pub *PublicKey) error { // nolint: interfacer
	return s.Signed.Open(context, pub)
}

// VerifyManyToOne verifies multiple signatures against a single context and
// message, returning true iff every signature is valid.
func VerifyManyToOne(context Context, message []byte, sigs []Signature) bool {
	// Our batch verify supports doing Ed25519ph/Ed25519ctx in bulk,
	// but we're stuck with this stupidity.
	msg, err := PrepareSignerMessage(context, message)
	if err != nil {
		return false
	}

	// Adapt from our wrapper types to the types used by the library.
	pks := make([]ed25519.PublicKey, 0, len(sigs))
	rawSigs := make([][]byte, 0, len(sigs))
	msgs := make([][]byte, 0, len(sigs))

	for i := range sigs {
		v := sigs[i] // This is deliberate.
		if v.PublicKey.isBlacklisted() {
			return false
		}

		pks = append(pks, ed25519.PublicKey(v.PublicKey[:]))
		rawSigs = append(rawSigs, v.Signature[:])
		msgs = append(msgs, msg)
	}

	allOk, _, err := ed25519.VerifyBatch(rand.Reader, pks, msgs, rawSigs, defaultOptions)
	if err != nil {
		return false
	}

	return allOk
}

// VerifyBatch verifies multiple signatures, made by multiple public keys,
// against a single context and multiple messages, returning true iff every
// signature is valid.
func VerifyBatch(context Context, messages [][]byte, sigs []Signature) bool {
	if len(messages) != len(sigs) {
		panic("signature: VerifyBatch messages/signature count mismatch")
	}

	// Adapt from our wrapper types to the types used by the library.
	pks := make([]ed25519.PublicKey, 0, len(sigs))
	rawSigs := make([][]byte, 0, len(sigs))
	msgs := make([][]byte, 0, len(sigs))

	for i := range sigs {
		v := sigs[i] // This is deliberate.
		if v.PublicKey.isBlacklisted() {
			return false
		}
		pks = append(pks, ed25519.PublicKey(v.PublicKey[:]))
		rawSigs = append(rawSigs, v.Signature[:])

		// Sigh. :(
		msg, err := PrepareSignerMessage(context, messages[i])
		if err != nil {
			return false
		}
		msgs = append(msgs, msg)
	}

	allOk, _, err := ed25519.VerifyBatch(rand.Reader, pks, msgs, rawSigs, defaultOptions)
	if err != nil {
		return false
	}

	return allOk
}

// RegisterTestPublicKey registers a hardcoded test public key with the
// internal public key blacklist.
func RegisterTestPublicKey(pk PublicKey) {
	testPublicKeys.Store(pk, true)
}

// BuildPublicKeyBlacklist builds the public key blacklist.
func BuildPublicKeyBlacklist(allowTestKeys bool) {
	if !allowTestKeys {
		testPublicKeys.Range(func(k, v interface{}) bool {
			blacklistedPublicKeys.Store(k, v)
			return true
		})
	}

	// Explicitly forbid other keys here.

	// Small order points.
	// See: https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L1019.
	for _, v := range []string{
		// 0 (order 4).
		"0000000000000000000000000000000000000000000000000000000000000000",
		// 1 (order 1).
		"0100000000000000000000000000000000000000000000000000000000000000",
		// 2707385501144840649318225287225658788936804267575313519463743609750303402022 (order 8).
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		// 55188659117513257062467267217118295137698188065244968500265048394206261417927 (order 8).
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		// p-1 (order 2).
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// p (=0, order 4).
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		// p+1 (=1, order 1).
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	} {
		var pk PublicKey
		if err := pk.UnmarshalHex(v); err != nil {
			panic(err)
		}

		blacklistedPublicKeys.Store(pk, true)
	}
}

// NewBlacklistedKey returns the PublicKey from the given hex or panics.
// The given key is also added to the blacklist.
func NewBlacklistedKey(hex string) PublicKey {
	var pk PublicKey
	if err := pk.UnmarshalHex(hex); err != nil {
		panic(err)
	}

	// Make sure that the key doesn't already exist in the blacklist.
	if pk.isBlacklisted() {
		panic("key already exists in blacklist, use another")
	}

	// Blacklist key.
	blacklistedPublicKeys.Store(pk, true)

	return pk
}
