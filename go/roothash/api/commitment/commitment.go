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
	commitmentSignatureContext = []byte("EkCommit")

	_ cbor.Marshaler   = (*Commitment)(nil)
	_ cbor.Unmarshaler = (*Commitment)(nil)
)

// Commitment is a roothash commitment.
type Commitment struct {
	signature.Signed

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
func (c *Commitment) Open() error {
	var header block.Header
	if err := c.Signed.Open(commitmentSignatureContext, &header); err != nil {
		return errors.New("roothash/commitment: commitment has invalid signature")
	}
	c.Header = &header

	return nil
}
