package pvss

import (
	"crypto/elliptic"
	"fmt"
	"io/ioutil"
	"os"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/share/pvss"

	"github.com/oasisprotocol/oasis-core/go/common/pem"
)

const (
	pointPEMType  = "EC PUBLIC KEY"
	scalarPEMType = "EC PRIVATE KEY"
	filePerm      = 0o600
)

// As convenient as it is to use kyber's PVSS implementation, scalars and
// points being interfaces makes s11n a huge pain, and mandates using
// wrapper types so that this can play nice with CBOR/JSON etc.
//
// Aut viam inveniam aut faciam.

// Point is an elliptic curve point.
type Point struct {
	inner kyber.Point
}

// Inner returns the actual kyber.Point.
func (p *Point) Inner() kyber.Point {
	return p.inner
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (p *Point) UnmarshalBinary(data []byte) error {
	inner := suite.Point()
	if err := inner.UnmarshalBinary(data); err != nil {
		return fmt.Errorf("pvss/s11n: failed to deserialize point: %w", err)
	}

	checkPoint := Point{inner: inner}
	if err := checkPoint.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: deserialized point is invalid: %w", err)
	}
	if checkPoint2, ok := inner.(isCanonicalAble); ok {
		// edwards25519.Point.IsCanonical takes a buffer, since points
		// that get serialized are always in canonical form.
		if !checkPoint2.IsCanonical(data) {
			return fmt.Errorf("pvss/s11n: point is not in canonical form")
		}
	}

	p.inner = inner

	return nil
}

// UnmarshalPEM decodes a PEM marshaled point.
func (p *Point) UnmarshalPEM(data []byte) error {
	b, err := pem.Unmarshal(pointPEMType, data)
	if err != nil {
		return fmt.Errorf("pvss/s11n: failed to deserialize PEM encoded point: %w", err)
	}

	return p.UnmarshalBinary(b)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (p Point) MarshalBinary() ([]byte, error) {
	if err := p.isWellFormed(); err != nil {
		return nil, fmt.Errorf("pvss/s11n: refusing to serialize invalid point: %w", err)
	}

	data, err := p.inner.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pvss/s11n: failed to serialize point: %w", err)
	}

	return data, nil
}

// MarshalPEM encodes a point into PEM form.
func (p Point) MarshalPEM() ([]byte, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return pem.Marshal(pointPEMType, b)
}

// LoadPEM loads a point from a PEM file on disk.  Iff the point is missing
// and a Scalar is provided, the Scalar's corresponding point will be written
// and loaded.
func (p *Point) LoadPEM(fn string, scalar *Scalar) error {
	f, err := os.Open(fn) //nolint: gosec
	if err != nil {
		if os.IsNotExist(err) && scalar != nil {
			if err = scalar.isWellFormed(); err != nil {
				return fmt.Errorf("pvss/s11n: refusing to use invalid scalar to generate point: %w", err)
			}
			pointInner := scalar.Point()
			p.inner = pointInner.Inner()

			var buf []byte
			if buf, err = p.MarshalPEM(); err != nil {
				return err
			}

			return ioutil.WriteFile(fn, buf, filePerm)
		}
		return err
	}
	defer f.Close() //nolint: errcheck

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("pvss/s11n: failed to read PEM serialized point: %w", err)
	}

	if err = p.UnmarshalPEM(buf); err != nil {
		return fmt.Errorf("pvss/s11n: failed to parse PEM serialized point: %w", err)
	}

	if scalar != nil {
		if err = scalar.isWellFormed(); err != nil {
			return fmt.Errorf("pvss/s11n: invalid scalar provided for verification: %w", err)
		}

		checkPoint := scalar.Point()
		if !p.Inner().Equal(checkPoint.Inner()) {
			return fmt.Errorf("pvss/s11n: point PEM is not for scalar")
		}
	}

	return nil
}

func (p *Point) isWellFormed() error {
	// Can never happen(?), but check anyway.
	if p.inner == nil {
		return fmt.Errorf("pvss/s11n: point is missing")
	}

	if !pointIsValid(p.inner) {
		return fmt.Errorf("pvss/s11n: point is invalid")
	}

	return nil
}

func pointFromKyber(p kyber.Point) Point {
	return Point{
		inner: p,
	}
}

type validAble interface {
	Valid() bool
}

type hasSmallOrderAble interface {
	HasSmallOrder() bool
}

type isCanonicalAble interface {
	IsCanonical([]byte) bool
}

func pointIsValid(point kyber.Point) bool {
	switch validator := point.(type) {
	case validAble:
		// P-256 point validation (ensures point is on curve)
		//
		// Note: Kyber's idea of a valid point includes the point at
		// infinity, which does not ensure contributory behavior when
		// doing ECDH.

		// We write out the point to binary data, and unmarshal
		// it with elliptic.Unmarshal, which checks to see if the
		// point is on the curve (while rejecting the point at
		// infinity).
		//
		// In theory, we could just examine the x/y coordinates, but
		// there's no way to get at those without reflection hacks.
		//
		// WARNING: If this ever needs to support NIST curves other
		// than P-256, this will need to get significantly more
		// involved.
		b, err := point.MarshalBinary()
		if err != nil {
			return false
		}
		if x, _ := elliptic.Unmarshal(elliptic.P256(), b); x == nil {
			return false
		}
		return true
	case hasSmallOrderAble:
		// Ed25519 point validation (rejects small-order points)
		return !validator.HasSmallOrder()
	default:
		return false
	}
}

// Scalar is a scalar.
type Scalar struct {
	inner kyber.Scalar
}

// Inner returns the actual kyber.Scalar.
func (s *Scalar) Inner() kyber.Scalar {
	return s.inner
}

// Point returns the corresponding point.
func (s *Scalar) Point() Point {
	if err := s.isWellFormed(); err != nil {
		panic(fmt.Errorf("pvss/s11n: malformed scalar for basepoint multiply: %w", err))
	}
	return pointFromKyber(suite.Point().Mul(s.Inner(), nil))
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	inner := suite.Scalar()
	if err := inner.UnmarshalBinary(data); err != nil {
		return fmt.Errorf("pvss/s11n: failed to deserialize scalar: %w", err)
	}

	s.inner = inner

	return nil
}

// UnmarshalPEM decodes a PEM marshaled scalar.
func (s *Scalar) UnmarshalPEM(data []byte) error {
	b, err := pem.Unmarshal(scalarPEMType, data)
	if err != nil {
		return fmt.Errorf("pvss/s11n: failed to deserialize PEM encoded scalar: %w", err)
	}

	return s.UnmarshalBinary(b)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (s Scalar) MarshalBinary() ([]byte, error) {
	data, err := s.inner.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pvss/s11n: failed to serialize scalar: %w", err)
	}

	return data, nil
}

// MarshalPEM encodes a scalar into PEM form.
func (s Scalar) MarshalPEM() ([]byte, error) {
	b, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return pem.Marshal(scalarPEMType, b)
}

// LoadOrGeneratePEM loads a scalar from a PEM file on disk.  Iff the
// scalar is missing, a new one will be generated, written, and loaded.
func (s *Scalar) LoadOrGeneratePEM(fn string) error {
	f, err := os.Open(fn) //nolint: gosec
	if err != nil {
		if os.IsNotExist(err) {
			var newScalar *Scalar
			if newScalar, _, err = NewKeyPair(); err != nil {
				return fmt.Errorf("pvss/s11n: failed to generate new scalar: %w", err)
			}
			s.inner = newScalar.inner

			var buf []byte
			if buf, err = s.MarshalPEM(); err != nil {
				return err
			}

			return ioutil.WriteFile(fn, buf, filePerm)
		}
		return err
	}
	defer f.Close() //nolint: errcheck

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("pvss/s11n: failed to read PEM serialized scalar: %w", err)
	}

	if err = s.UnmarshalPEM(buf); err != nil {
		return fmt.Errorf("pvss/s11n: failed to parse PEM serialized scalar: %w", err)
	}
	if err = s.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: deserialized scalar is invalid: %w", err)
	}

	return nil
}

func (s *Scalar) isWellFormed() error {
	// Can never happen(?), but check anyway.
	if s.inner == nil {
		return fmt.Errorf("pvss/s11n: scalar is missing")
	}

	return nil
}

func scalarFromKyber(s kyber.Scalar) Scalar {
	return Scalar{
		inner: s,
	}
}

// PubVerShare is a public verifiable share (`pvss.PubVerShare`)
type PubVerShare struct {
	V Point `json:"v"` // Encrypted/decrypted share

	C  Scalar `json:"c"`  // Challenge
	R  Scalar `json:"r"`  // Response
	VG Point  `json:"vg"` // Public commitment with respect to base point G
	VH Point  `json:"vh"` // Public commitment with respect to base point H
}

func (pvs *PubVerShare) isWellFormed() error {
	if err := pvs.V.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: invalid PubVerShare V: %w", err)
	}
	if err := pvs.C.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: invalid PubVerShare C: %w", err)
	}
	if err := pvs.R.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: invalid PubVerShare R: %w", err)
	}
	if err := pvs.VG.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: invalid PubVerShare VG: %w", err)
	}
	if err := pvs.VH.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: invalid PubVerShare VH: %w", err)
	}

	return nil
}

func (pvs *PubVerShare) toKyber(index int) *pvss.PubVerShare {
	return &pvss.PubVerShare{
		S: share.PubShare{
			I: index,
			V: pvs.V.Inner(),
		},
		P: dleq.Proof{
			C:  pvs.C.Inner(),
			R:  pvs.R.Inner(),
			VG: pvs.VG.Inner(),
			VH: pvs.VH.Inner(),
		},
	}
}

func pubVerShareFromKyber(pvs *pvss.PubVerShare) *PubVerShare {
	return &PubVerShare{
		V:  pointFromKyber(pvs.S.V),
		C:  scalarFromKyber(pvs.P.C),
		R:  scalarFromKyber(pvs.P.R),
		VG: pointFromKyber(pvs.P.VG),
		VH: pointFromKyber(pvs.P.VH),
	}
}

// CommitShare is a commit share.
type CommitShare struct {
	PolyV Point `json:"poly_v"` // Share of the public commitment polynomial
	PubVerShare
}

func (cs *CommitShare) isWellFormed() error {
	if err := cs.PolyV.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: invalid CommitShare PolyV: %w", err)
	}
	if err := cs.PubVerShare.isWellFormed(); err != nil {
		return fmt.Errorf("pvss/s11n: invalid CommitShare PubVerShare: %w", err)
	}

	return nil
}

func (cs *CommitShare) toKyber(index int) (*share.PubShare, *pvss.PubVerShare) {
	pubShare := &share.PubShare{
		I: index,
		V: cs.PolyV.Inner(),
	}
	return pubShare, cs.PubVerShare.toKyber(index)
}

func commitShareFromKyber(pubPolyShare *share.PubShare, encShare *pvss.PubVerShare) *CommitShare {
	return &CommitShare{
		PolyV:       pointFromKyber(pubPolyShare.V),
		PubVerShare: *pubVerShareFromKyber(encShare),
	}
}

func commitSharesFromKyber(pubPolyShares []*share.PubShare, encShares []*pvss.PubVerShare) []*CommitShare {
	if len(pubPolyShares) != len(encShares) {
		panic("pvss/s11n: BUG: len(pubPolyShares != len(encShares)")
	}

	var shares []*CommitShare
	for i, pubPolyShare := range pubPolyShares {
		encShare := encShares[i]
		if pubPolyShare.I != encShare.S.I {
			panic("pvss/s11n: BUG: pubPolyShare.I != encShare.I")
		}
		shares = append(shares, commitShareFromKyber(pubPolyShare, encShare))
	}

	return shares
}
