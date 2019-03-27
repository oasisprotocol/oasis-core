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
	SignatureContext = []byte("EkCommi2")

	_ cbor.Marshaler   = (*Commitment)(nil)
	_ cbor.Unmarshaler = (*Commitment)(nil)
)

// Message holds the data signed in a commitment
type Message struct {
	Header block.Header
	RakSig signature.RawSignature
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (m *Message) MarshalCBOR() []byte {
	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes a CBOR marshaled message.
func (m *Message) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, m)
}

// Commitment is a roothash commitment.
type Commitment struct {
	signature.Signed
}

// OpenCommitment is a commitment that has been verified and deserialized.
//
// The open commitment still contains the original signed commitment.
type OpenCommitment struct {
	Commitment

	Message *Message `codec:"message"`
}

// FromOpaqueCommitment deserializes a opaque commitment into a commitment.
func (c *Commitment) FromOpaqueCommitment(commit *api.OpaqueCommitment) error {
	return c.UnmarshalCBOR(commit.Data)
}

// ToOpaqueCommitment serializes a commitment into an opaque commitment.
func (c *Commitment) ToOpaqueCommitment() *api.OpaqueCommitment {
	return &api.OpaqueCommitment{Data: c.MarshalCBOR()}
}

// Open validates the commitment signature, and de-serializes the message. This does not validate the RAK signature.
func (c *Commitment) Open() (*OpenCommitment, error) {
	var message Message
	if err := c.Signed.Open(SignatureContext, &message); err != nil {
		return nil, errors.New("roothash/commitment: commitment has invalid signature")
	}

	return &OpenCommitment{
		Commitment: *c,
		Message:    &message,
	}, nil
}

// SignCommitment serializes the message and signs the commitment.
func SignCommitment(privateKey signature.PrivateKey, message *Message) (*Commitment, error) {
	signed, err := signature.SignSigned(privateKey, SignatureContext, message)
	if err != nil {
		return nil, err
	}

	return &Commitment{
		Signed: *signed,
	}, nil
}
