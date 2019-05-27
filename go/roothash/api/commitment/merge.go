// Package commitment defines a roothash commitment.
package commitment

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
)

// MergeSignatureContext is the signature context used to sign merge
// worker commitments.
var MergeSignatureContext = []byte("EkCommMC")

type MergeBody struct {
	ComputeCommits []ComputeCommitment `codec:"commits"`
	Header         block.Header        `codec:"header"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (m *MergeBody) MarshalCBOR() []byte {
	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes a CBOR marshaled message.
func (m *MergeBody) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, m)
}

// MergeCommitment is a roothash commitment from a merge worker.
//
// The signed content is MergeBody.
type MergeCommitment struct {
	signature.Signed
}

// OpenMergeCommitment is a merge commitment that has been verified and
// deserialized.
//
// The open commitment still contains the original signed commitment.
type OpenMergeCommitment struct {
	MergeCommitment

	Body *MergeBody `codec:"body"`
}

// Open validates the merge commitment signature, and de-serializes the body.
func (c *MergeCommitment) Open() (*OpenMergeCommitment, error) {
	var body MergeBody
	if err := c.Signed.Open(MergeSignatureContext, &body); err != nil {
		return nil, errors.New("roothash/commitment: merge commitment has invalid signature")
	}

	return &OpenMergeCommitment{
		MergeCommitment: *c,
		Body:            &body,
	}, nil
}

// SignMergeCommitment serializes the message and signs the commitment.
func SignMergeCommitment(privateKey signature.PrivateKey, body *MergeBody) (*MergeCommitment, error) {
	signed, err := signature.SignSigned(privateKey, MergeSignatureContext, body)
	if err != nil {
		return nil, err
	}

	return &MergeCommitment{
		Signed: *signed,
	}, nil
}

func init() {
	cbor.RegisterType(OpenMergeCommitment{}, "com.oasislabs/OpenMergeCommitment")
}
