// Package commitment defines a roothash commitment.
package commitment

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
)

var (
	// SignatureContext is the signature context used to sign commitments.
	SignatureContext = []byte("EkCommit")

	_ cbor.Marshaler   = (*Commitment)(nil)
	_ cbor.Unmarshaler = (*Commitment)(nil)
)

// Commitment is a roothash commitment.
type Commitment struct {
	signature.Signed
}

// OpenCommitment is a commitment that has been verified and deserialized.
//
// The open commitment still contains the original signed commitment.
type OpenCommitment struct {
	Commitment

	Header *block.Header `codec:"header"`
}

// FromOpaqueCommitment deserializes a opaque commitment into a commitment.
func (c *Commitment) FromOpaqueCommitment(commit *api.OpaqueCommitment) error {
	return c.UnmarshalCBOR(commit.Data)
}

// ToOpaqueCommitment serializes a commitment into an opaque commitment.
func (c *Commitment) ToOpaqueCommitment() *api.OpaqueCommitment {
	return &api.OpaqueCommitment{Data: c.MarshalCBOR()}
}

// Open validates the commitment signature, and de-serializes the header.
func (c *Commitment) Open() (*OpenCommitment, error) {
	var header block.Header
	if err := c.Signed.Open(SignatureContext, &header); err != nil {
		return nil, errors.New("roothash/commitment: commitment has invalid signature")
	}

	return &OpenCommitment{
		Commitment: *c,
		Header:     &header,
	}, nil
}

// SignCommitment serializes the header and signs the commitment.
func SignCommitment(privateKey signature.PrivateKey, header *block.Header) (*Commitment, error) {
	signed, err := signature.SignSigned(privateKey, SignatureContext, header)
	if err != nil {
		return nil, err
	}

	return &Commitment{
		Signed: *signed,
	}, nil
}
