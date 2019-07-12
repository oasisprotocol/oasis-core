// Package commitment defines a roothash commitment.
package commitment

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
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

// MostlyEqual returns true if the commitment is mostly equal to another
// specified commitment as per discrepancy detection criteria.
func (c OpenMergeCommitment) MostlyEqual(other OpenCommitment) bool {
	return c.Body.Header.MostlyEqual(&other.(OpenMergeCommitment).Body.Header)
}

// ToVote returns a hash that represents a vote for this commitment as
// per discrepancy resolution criteria.
func (c OpenMergeCommitment) ToVote() hash.Hash {
	return c.Body.Header.EncodedHash()
}

// ToDDResult returns a commitment-specific result after discrepancy
// detection.
func (c OpenMergeCommitment) ToDDResult() interface{} {
	return c.Body.Header
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
func SignMergeCommitment(signer signature.Signer, body *MergeBody) (*MergeCommitment, error) {
	signed, err := signature.SignSigned(signer, MergeSignatureContext, body)
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
