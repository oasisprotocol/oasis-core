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
	// ComputeSignatureContext is the signature context used to sign compute
	// worker commitments.
	ComputeSignatureContext = []byte("EkCommCC")

	_ cbor.Marshaler   = (*ComputeCommitment)(nil)
	_ cbor.Unmarshaler = (*ComputeCommitment)(nil)
)

// ComputeBody holds the data signed in a compute worker commitment.
type ComputeBody struct {
	Header block.Header
	RakSig signature.RawSignature
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (m *ComputeBody) MarshalCBOR() []byte {
	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes a CBOR marshaled message.
func (m *ComputeBody) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, m)
}

// ComputeCommitment is a roothash commitment from a compute worker.
type ComputeCommitment struct {
	signature.Signed
}

// OpenComputeCommitment is a compute commitment that has been verified and
// deserialized.
//
// The open commitment still contains the original signed commitment.
type OpenComputeCommitment struct {
	ComputeCommitment

	Body *ComputeBody `codec:"body"`
}

// FromOpaqueCommitment deserializes a opaque commitment into a compute commitment.
func (c *ComputeCommitment) FromOpaqueCommitment(commit *api.OpaqueCommitment) error {
	return c.UnmarshalCBOR(commit.Data)
}

// ToOpaqueCommitment serializes a compute commitment into an opaque commitment.
func (c *ComputeCommitment) ToOpaqueCommitment() *api.OpaqueCommitment {
	return &api.OpaqueCommitment{Data: c.MarshalCBOR()}
}

// Open validates the compute commitment signature, and de-serializes the message.
// This does not validate the RAK signature.
func (c *ComputeCommitment) Open() (*OpenComputeCommitment, error) {
	var body ComputeBody
	if err := c.Signed.Open(ComputeSignatureContext, &body); err != nil {
		return nil, errors.New("roothash/commitment: commitment has invalid signature")
	}

	return &OpenComputeCommitment{
		ComputeCommitment: *c,
		Body:              &body,
	}, nil
}

// SignComputeCommitment serializes the message and signs the commitment.
func SignComputeCommitment(privateKey signature.PrivateKey, body *ComputeBody) (*ComputeCommitment, error) {
	signed, err := signature.SignSigned(privateKey, ComputeSignatureContext, body)
	if err != nil {
		return nil, err
	}

	return &ComputeCommitment{
		Signed: *signed,
	}, nil
}
