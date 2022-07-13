package sigstruct

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

const (
	sigstructSize = 1808

	headerOffset         = 0
	vendorOffset         = 16
	dateOffset           = 20
	header2Offset        = 24
	swdefinedOffset      = 40
	modulusOffset        = 128
	exponentOffset       = 512
	signatureOffset      = 516
	miscSelectOffset     = 900
	miscSelectMaskOffset = 904
	attributesOffset     = 928
	attributesMaskOffset = 944
	enclaveHashOffset    = 960
	isvProdIDOffset      = 1024
	isvSVNOffset         = 1026
	q1Offset             = 1040
	q2Offset             = 1424
)

var (
	header         = []byte{0x06, 0x00, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}
	header2        = []byte{0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	vendorNonIntel = []byte{0x00, 0x00, 0x00, 0x00}

	requiredExponent = 3
)

// Sigstruct is an SGX enclave SIGSTRUCT.
//
// The most recent version of the Intel documentation defines more fields
// that were formerly reserved, however support for setting such things
// is currently not implemented.
type Sigstruct struct { //nolint: maligned
	BuildDate      time.Time
	SwDefined      [4]byte
	MiscSelect     uint32
	MiscSelectMask uint32
	Attributes     sgx.Attributes
	AttributesMask [2]uint64
	EnclaveHash    sgx.MrEnclave
	ISVProdID      uint16
	ISVSVN         uint16
}

// Sign signs the SIGSTRUCT with the provided private key.
func (s *Sigstruct) Sign(privateKey *rsa.PrivateKey) ([]byte, error) {
	// Check that the private key is sensible.
	if e := privateKey.E; e != requiredExponent {
		return nil, fmt.Errorf("sgx/sigstruct: invalid private key exponent: %v", e)
	}
	if bits := privateKey.Size(); bits != sgx.ModulusSize/8 {
		return nil, fmt.Errorf("sgx/sigstruct: invalid RSA key size: %v", bits)
	}

	// Marshal the sigstruct to binary.
	buf := s.toUnsigned()

	// Generate the signature.
	hashed := hashForSignature(buf)
	rawSig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, fmt.Errorf("sgx/sigstruct: RSA signing failed: %w", err)
	}

	// Generate the pre-computed bullshit.
	sigBytes, q1Bytes, q2Bytes, err := postProcessSignature(rawSig, privateKey.N)
	if err != nil {
		return nil, err
	}

	// Fill out the rest of the SIGSTRUCT.
	modBytes, _ := sgx.To3072le(privateKey.N, false)                          // Can't fail.
	copy(buf[modulusOffset:], modBytes)                                       // MODULUS
	binary.LittleEndian.PutUint32(buf[exponentOffset:], uint32(privateKey.E)) // EXPONENT
	copy(buf[signatureOffset:], sigBytes)                                     // SIGNATURE
	copy(buf[q1Offset:], q1Bytes)                                             // Q1
	copy(buf[q2Offset:], q2Bytes)                                             // Q2

	return buf, nil
}

// HashForSignature returns the SHA-256 hash that is to be signed.
//
// This method can be used for offline signing.
func (s *Sigstruct) HashForSignature() []byte {
	return hashForSignature(s.toUnsigned())
}

// WithSignature combines the provided raw signature (which must be over the result of an earlier
// call to HashForSignature) with the given SIGSTRUCT.
//
// The SIGSTRUCT that was signed MUST match this structure and an error will be returned otherwise
// to prevent returning a malformed SIGSTRUCT.
//
// This method can be used after an offline signing process has produced a signature.
func (s *Sigstruct) WithSignature(rawSig []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	// Marshal the sigstruct to binary.
	buf := s.toUnsigned()

	// Generate the pre-computed bullshit.
	sigBytes, q1Bytes, q2Bytes, err := postProcessSignature(rawSig, pubKey.N)
	if err != nil {
		return nil, err
	}

	// Fill out the rest of the SIGSTRUCT.
	modBytes, _ := sgx.To3072le(pubKey.N, false)                          // Can't fail.
	copy(buf[modulusOffset:], modBytes)                                   // MODULUS
	binary.LittleEndian.PutUint32(buf[exponentOffset:], uint32(pubKey.E)) // EXPONENT
	copy(buf[signatureOffset:], sigBytes)                                 // SIGNATURE
	copy(buf[q1Offset:], q1Bytes)                                         // Q1
	copy(buf[q2Offset:], q2Bytes)                                         // Q2

	// Verify signed SIGSTRUCT.
	if _, _, err = Verify(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func hashForSignature(buf []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(buf[:modulusOffset])
	_, _ = h.Write(buf[miscSelectOffset : isvSVNOffset+2])
	return h.Sum(nil)
}

func postProcessSignature(raw []byte, modulus *big.Int) (sigBytes, q1Bytes, q2Bytes []byte, err error) {
	var sig big.Int
	sig.SetBytes(raw)

	if sigBytes, err = sgx.To3072le(&sig, true); err != nil {
		return nil, nil, nil, fmt.Errorf("sgx/sigstruct: failed to serialize signature: %w", err)
	}

	q1, q2 := deriveQ1Q2(&sig, modulus)
	if q1Bytes, err = sgx.To3072le(q1, true); err != nil {
		return nil, nil, nil, fmt.Errorf("sgx/sigstruct: failed to serialize q1: %w", err)
	}
	if q2Bytes, err = sgx.To3072le(q2, true); err != nil {
		return nil, nil, nil, fmt.Errorf("sgx/sigstruct: failed to serialize q2: %w", err)
	}

	return
}

func deriveQ1Q2(sig, modulus *big.Int) (*big.Int, *big.Int) {
	// q1 = floor(Signature^2 / Modulus);
	// q2 = floor((Signature^3 - q1 * Signature * Modulus) / Modulus);
	var q1, q2, toSub big.Int
	q1.Mul(sig, sig)     // q1 = sig^2
	q2.Mul(&q1, sig)     // q2 = sig^3
	q1.Div(&q1, modulus) // q1 = floor(q1 / modulus)

	toSub.Mul(&q1, sig)        // toSub = q1 * sig
	toSub.Mul(&toSub, modulus) // toSub = toSub * modulus
	q2.Sub(&q2, &toSub)        // q2 = q2 - toSub
	q2.Div(&q2, modulus)       // floor(q2 = q2 / modulus)

	return &q1, &q2
}

func (s *Sigstruct) toUnsigned() []byte {
	var buf [sigstructSize]byte

	// See:
	//  Intel 64 and IA-32 Architectures Software Developer’s Manual
	//  37.14 ENCLAVE SIGNATURE STRUCTURE (SIGSTRUCT)
	copy(buf[headerOffset:], header)                                        // HEADER
	copy(buf[vendorOffset:], vendorNonIntel)                                // VENDOR
	binary.LittleEndian.PutUint32(buf[dateOffset:], toBcdDate(s.BuildDate)) // DATE
	copy(buf[header2Offset:], header2)                                      // HEADER2
	copy(buf[swdefinedOffset:], s.SwDefined[:])                             // SWDEFINED
	// RESERVED
	// MODULUS (Not covered by signature)
	// EXPONENT (Not covered by signature)
	// SIGNATURE (Not covered by signature)
	binary.LittleEndian.PutUint32(buf[miscSelectOffset:], s.MiscSelect)         // MISCSELECT
	binary.LittleEndian.PutUint32(buf[miscSelectMaskOffset:], s.MiscSelectMask) // MISCMASK
	// CET_ATTRIBUTES
	// CET_ATTRIBUTES_MASK
	// RESERVED
	// ISVFAMILYID
	binary.LittleEndian.PutUint64(buf[attributesOffset:], uint64(s.Attributes.Flags)) // ATTRIBUTES (flags)
	binary.LittleEndian.PutUint64(buf[attributesOffset+8:], s.Attributes.Xfrm)        // ATTRIBUTES (xfrm)
	binary.LittleEndian.PutUint64(buf[attributesMaskOffset:], s.AttributesMask[0])    // ATTRIBUTEMASK (flags)
	binary.LittleEndian.PutUint64(buf[attributesMaskOffset+8:], s.AttributesMask[1])  // ATTRIBUTEMASK (xfrm)
	copy(buf[enclaveHashOffset:], s.EnclaveHash[:])                                   // ENCLAVEHASH
	// RESERVED
	// ISVEXTPRODID
	binary.LittleEndian.PutUint16(buf[isvProdIDOffset:], s.ISVProdID) // ISVPRODID
	binary.LittleEndian.PutUint16(buf[isvSVNOffset:], s.ISVSVN)       // ISVSVN
	// RESERVED
	// Q1 (Not covered by signature)
	// Q2 (Not covered by signature)

	return buf[:]
}

func toBcdDate(t time.Time) uint32 {
	// The DATE field is encoded as yyyymmdd BCD, little endian.
	y, m, d := t.Date()
	s := fmt.Sprintf("%04d%02d%02d", y, m, d)
	v, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(v)
}

func fromBcdDate(v uint32) (time.Time, error) {
	s := fmt.Sprintf("%08x", v)
	t, err := time.ParseInLocation("20060102", s, time.UTC)
	if err != nil {
		return t, fmt.Errorf("sgx/sigstruct: malformed date: %w", err)
	}
	return t, nil
}

// Verify validates a byte serialized SIGSTRUCT, and returns the signing public
// key and parsed SIGSTRUCT.
//
// Note: The returned SIGSTRUCT omits fields not currently used.
func Verify(buf []byte) (*rsa.PublicKey, *Sigstruct, error) {
	// Ensure the length is as expected.  This lets us omit error checking
	// when deserializing big ints.
	if sz := len(buf); sz != sigstructSize {
		return nil, nil, fmt.Errorf("sgx/sigstruct: buffer is not %v bytes: %v", sigstructSize, sz)
	}

	// Extract and validate the public key/signature.
	var pubKey rsa.PublicKey
	pubKey.N, _ = sgx.From3072le(buf[modulusOffset:exponentOffset])
	if bitLen := pubKey.N.BitLen(); bitLen != sgx.ModulusSize {
		return nil, nil, fmt.Errorf("sgx/sigstruct: public key modulus is not %v bits: %v", sgx.ModulusSize, bitLen)
	}
	pubKey.E = int(binary.LittleEndian.Uint32(buf[exponentOffset:]))
	if pubKey.E != requiredExponent {
		return nil, nil, fmt.Errorf("sgx/sigstruct: public key exponent is not %v: %v", requiredExponent, pubKey.E)
	}

	sigBig, _ := sgx.From3072le(buf[signatureOffset:miscSelectOffset])
	sigBytes := sigBig.Bytes()
	if padLen := sgx.ModulusSize/8 - len(sigBytes); padLen > 0 {
		sigBytes = append(make([]byte, padLen), sigBytes...)
	}

	hashed := hashForSignature(buf)
	if err := rsa.VerifyPKCS1v15(&pubKey, crypto.SHA256, hashed, sigBytes); err != nil {
		return nil, nil, fmt.Errorf("sgx/sigstruct: invalid signature: %w", err)
	}

	// Ensure that Q1/Q2 are sane.
	derivedQ1, derivedQ2 := deriveQ1Q2(sigBig, pubKey.N)
	q1, _ := sgx.From3072le(buf[q1Offset:q2Offset])
	q2, _ := sgx.From3072le(buf[q2Offset:])
	if q1.Cmp(derivedQ1) != 0 {
		return nil, nil, fmt.Errorf("sgx/sigstruct: invalid Q1")
	}
	if q2.Cmp(derivedQ2) != 0 {
		return nil, nil, fmt.Errorf("sgx/sigstruct: invalid Q2")
	}

	var (
		s   Sigstruct
		err error
	)
	if s.BuildDate, err = fromBcdDate(binary.LittleEndian.Uint32(buf[dateOffset:])); err != nil {
		return nil, nil, err
	}
	copy(s.SwDefined[:], buf[swdefinedOffset:])
	s.MiscSelect = binary.LittleEndian.Uint32(buf[miscSelectOffset:])
	s.MiscSelectMask = binary.LittleEndian.Uint32(buf[miscSelectMaskOffset:])
	s.Attributes.Flags = sgx.AttributesFlags(binary.LittleEndian.Uint64(buf[attributesOffset:]))
	s.Attributes.Xfrm = binary.LittleEndian.Uint64(buf[attributesOffset+8:])
	s.AttributesMask[0] = binary.LittleEndian.Uint64(buf[attributesMaskOffset:])
	s.AttributesMask[1] = binary.LittleEndian.Uint64(buf[attributesMaskOffset+8:])
	copy(s.EnclaveHash[:], buf[enclaveHashOffset:])
	s.ISVProdID = binary.LittleEndian.Uint16(buf[isvProdIDOffset:])
	s.ISVSVN = binary.LittleEndian.Uint16(buf[isvSVNOffset:])

	return &pubKey, &s, nil
}

// Option is an option used when constructing a Sigstruct.
type Option func(*Sigstruct)

// WithBuildDate sets the BUILDDATE field.
func WithBuildDate(date time.Time) Option {
	return func(s *Sigstruct) {
		s.BuildDate = date
	}
}

// WithSwDefined sets the SWDEFINED field.
func WithSwDefined(swDefined [4]byte) Option {
	return func(s *Sigstruct) {
		s.SwDefined = swDefined
	}
}

// WithMiscSelect sets the MISCSELECT field.
func WithMiscSelect(miscSelect uint32) Option {
	return func(s *Sigstruct) {
		s.MiscSelect = miscSelect
	}
}

// WithMiscSelectMask sets the MISCSELECTMASK field.
func WithMiscSelectMask(miscSelectMask uint32) Option {
	return func(s *Sigstruct) {
		s.MiscSelectMask = miscSelectMask
	}
}

// WithAttributes sets the ATTRIBUTES field.
func WithAttributes(attributes sgx.Attributes) Option {
	return func(s *Sigstruct) {
		s.Attributes = attributes
	}
}

// WithAttributesMask sets the ATTRIBUTESMASK field.
func WithAttributesMask(attributesMask [2]uint64) Option {
	return func(s *Sigstruct) {
		s.AttributesMask = attributesMask
	}
}

// WithEnclaveHash sets the ENCLAVEHASH field.
func WithEnclaveHash(enclaveHash sgx.MrEnclave) Option {
	return func(s *Sigstruct) {
		s.EnclaveHash = enclaveHash
	}
}

// WithISVProdID sets the ISVPRODID field.
func WithISVProdID(isvProdID uint16) Option {
	return func(s *Sigstruct) {
		s.ISVProdID = isvProdID
	}
}

// WithISVSVN sets the ISVSVN field.
func WithISVSVN(isvSVN uint16) Option {
	return func(s *Sigstruct) {
		s.ISVSVN = isvSVN
	}
}

// New creates a new Sigstruct ready to be signed.
func New(opts ...Option) *Sigstruct {
	var s Sigstruct
	for _, v := range opts {
		v(&s)
	}

	return &s
}
