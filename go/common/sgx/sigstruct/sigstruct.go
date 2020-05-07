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

	"github.com/oasislabs/oasis-core/go/common/sgx"
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
	h := sha256.New()
	_, _ = h.Write(buf[:modulusOffset])
	_, _ = h.Write(buf[miscSelectOffset : isvSVNOffset+2])
	hashed := h.Sum(nil)
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

func postProcessSignature(raw []byte, modulus *big.Int) (sigBytes, q1Bytes, q2Bytes []byte, err error) {
	var sig big.Int
	sig.SetBytes(raw)

	if sigBytes, err = sgx.To3072le(&sig, true); err != nil {
		return nil, nil, nil, fmt.Errorf("sgx/sigstruct: failed to serialize signature: %w", err)
	}

	// q1 = floor(Signature^2 / Modulus);
	// q2 = floor((Signature^3 - q1 * Signature * Modulus) / Modulus);
	var q1, q2, toSub big.Int
	q1.Mul(&sig, &sig)   // q1 = sig^2
	q2.Mul(&q1, &sig)    // q2 = sig^3
	q1.Div(&q1, modulus) // q1 = floor(q1 / modulus)

	toSub.Mul(&q1, &sig)       // toSub = q1 * sig
	toSub.Mul(&toSub, modulus) // toSub = toSub * modulus
	q2.Sub(&q2, &toSub)        // q2 = q2 - toSub
	q2.Div(&q2, modulus)       // floor(q2 = q2 / modulus)

	if q1Bytes, err = sgx.To3072le(&q1, true); err != nil {
		return nil, nil, nil, fmt.Errorf("sgx/sigstruct: failed to serialize q1: %w", err)
	}
	if q2Bytes, err = sgx.To3072le(&q2, true); err != nil {
		return nil, nil, nil, fmt.Errorf("sgx/sigstruct: failed to serialize q2: %w", err)
	}

	return
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
