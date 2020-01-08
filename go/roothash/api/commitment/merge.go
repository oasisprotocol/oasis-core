// Package commitment defines a roothash commitment.
package commitment

import (
	"errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
)

// MergeSignatureContext is the signature context used to sign merge
// worker commitments.
var MergeSignatureContext = signature.NewContext("oasis-core/roothash: merge commitment", signature.WithChainSeparation())

type MergeBody struct {
	ExecutorCommits []ExecutorCommitment `json:"commits"`
	Header          block.Header         `json:"header"`
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

	Body *MergeBody `json:"body"`
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
