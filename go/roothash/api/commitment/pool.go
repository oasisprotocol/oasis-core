package commitment

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

var (
	ErrNoRuntime              = errors.New("roothash/commitment: no runtime configured")
	ErrNoCommittee            = errors.New("roothash/commitment: no committee configured")
	ErrInvalidCommitteeKind   = errors.New("roothash/commitment: invalid committee kind")
	ErrRakSigInvalid          = errors.New("roothash/commitment: batch RAK signature invalid")
	ErrNotInCommittee         = errors.New("roothash/commitment: node not part of committee")
	ErrAlreadyCommitted       = errors.New("roothash/commitment: node already sent commitment")
	ErrNoNodeVerifyPolicy     = errors.New("roothash/commitment: no node verify policy")
	ErrNoStorageVerifyPolicy  = errors.New("roothash/commitment: no storage verify policy")
	ErrNotBasedOnCorrectBlock = errors.New("roothash/commitment: submitted commitment is not based on correct block")
	ErrDiscrepancyDetected    = errors.New("roothash/commitment: discrepancy detected")
	ErrStillWaiting           = errors.New("roothash/commitment: still waiting for commits")
	ErrInsufficientVotes      = errors.New("roothash/commitment: insufficient votes to finalize discrepancy resolution round")
)

// NodeVerifyPolicy is a function defining the policy for accepting
// commitments from nodes.
type NodeVerifyPolicy func(*scheduler.CommitteeNode) error

// StorageVerifyPolicy is a function defining the policy for verifying
// storage receipts in commitments from nodes.
type StorageVerifyPolicy func(signature.PublicKey) error

// NodeInfo contains information about a node that is member of a committee.
type NodeInfo struct {
	// CommitteeNode is an index into the Committee.Members structure.
	CommitteeNode int           `codec:"committee_node"`
	Runtime       *node.Runtime `codec:"runtime"`
}

// Pool is a serializable pool of commiments that can be used to perform
// discrepancy detection.
//
// The pool is not safe for concurrent use.
type Pool struct {
	// Runtime is the runtime descriptor this pool is collecting the
	// commitments for.
	Runtime *registry.Runtime `codec:"runtime"`
	// Committee is the committee this pool is collecting the commitments for.
	Committee *scheduler.Committee `codec:"committee"`
	// NodeInfo contains node information about committee members.
	NodeInfo map[signature.MapKey]NodeInfo `codec:"node_info"`
	// Commitments are the commitments in the pool.
	//
	// The stored commitment must be an *OpenComputeCommitment.
	Commitments map[signature.MapKey]interface{} `codec:"commitments"`
	// NodeVerifyPolicy is a function defining the policy for accepting
	// commitments from nodes. If no policy is defined, all commitments will
	// be rejected.
	NodeVerifyPolicy NodeVerifyPolicy `codec:"-"`
	// StorageVerifyPolicy is a function defining the policy for verifying
	// storage receipts in commitments from nodes. If no policy is defined,
	// all commitments will be rejected.
	StorageVerifyPolicy StorageVerifyPolicy `codec:"-"`
}

func (p *Pool) getRole(id signature.MapKey) (scheduler.Role, error) {
	ni, ok := p.NodeInfo[id]
	if !ok {
		return scheduler.Invalid, ErrNotInCommittee
	}

	if p.NodeVerifyPolicy == nil {
		return scheduler.Invalid, ErrNoNodeVerifyPolicy
	}

	n := p.Committee.Members[ni.CommitteeNode]
	if err := p.NodeVerifyPolicy(n); err != nil {
		return scheduler.Invalid, err
	}

	return n.Role, nil
}

// ResetCommitments resets the commitments in the pool.
func (p *Pool) ResetCommitments() {
	if p.Commitments == nil || len(p.Commitments) > 0 {
		p.Commitments = make(map[signature.MapKey]interface{})
	}
}

// AddComputeCommitment verifies and adds a new compute commitment to the pool.
func (p *Pool) AddComputeCommitment(blk *block.Block, commitment *ComputeCommitment) error {
	if p.Committee == nil {
		return ErrNoCommittee
	}
	if p.Committee.Kind != scheduler.Compute {
		return ErrInvalidCommitteeKind
	}

	id := commitment.Signature.PublicKey.ToMapKey()

	// Check node identity/role.
	role, err := p.getRole(id)
	if err != nil {
		return err
	}

	// Check the commitment signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return err
	}
	body := openCom.Body
	header := &body.Header

	if p.Runtime == nil {
		return ErrNoRuntime
	}

	// Verify RAK-attestation.
	if p.Runtime.TEEHardware != node.TEEHardwareInvalid {
		rak := p.NodeInfo[id].Runtime.Capabilities.TEE.RAK
		batchSigMessage := block.BatchSigMessage{
			PreviousBlock: *blk,
			IORoot:        header.IORoot,
			StateRoot:     header.StateRoot,
		}
		if !rak.Verify(api.RakSigContext, cbor.Marshal(batchSigMessage), body.RakSig[:]) {
			return ErrRakSigInvalid
		}
	}

	// Ensure the node did not already submit a commitment.
	if _, ok := p.Commitments[id]; ok {
		return ErrAlreadyCommitted
	}

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&blk.Header) {
		return ErrNotBasedOnCorrectBlock
	}

	// Check if the header refers to hashes in storage.
	if p.StorageVerifyPolicy == nil {
		return ErrNoStorageVerifyPolicy
	}
	if role == scheduler.Leader || role == scheduler.BackupWorker {
		if err = p.StorageVerifyPolicy(header.StorageReceipt.PublicKey); err != nil {
			return err
		}

		if err = header.VerifyStorageReceiptSignature(); err != nil {
			return err
		}
	}

	if p.Commitments == nil {
		p.Commitments = make(map[signature.MapKey]interface{})
	}
	p.Commitments[id] = *openCom

	return nil
}

// CheckEnoughComputeCommitments checks if there is enough compute commitments in
// the pool to be able to perform discrepancy detection.
func (p *Pool) CheckEnoughComputeCommitments(wantPrimary, didTimeout bool) error {
	if p.Committee == nil {
		return ErrNoCommittee
	}

	var commits, required int
	for _, n := range p.Committee.Members {
		var check bool
		if wantPrimary {
			check = n.Role == scheduler.Worker || n.Role == scheduler.Leader
		} else {
			check = n.Role == scheduler.BackupWorker
		}
		if !check {
			continue
		}

		required++
		if _, ok := p.Commitments[n.PublicKey.ToMapKey()]; ok {
			commits++
		}
	}

	// While a timer is running, all nodes are required to answer.
	//
	// After the timeout has elapsed, a limited number of stragglers
	// are allowed.
	if didTimeout {
		required -= int(p.Runtime.ReplicaAllowedStragglers)
	}

	if commits < required {
		return ErrStillWaiting
	}

	return nil
}

// DetectComputeDiscrepancy performs discrepancy detection on the current compute
// commitments in the pool.
//
// The caller must verify that there is enough commitments in the pool.
func (p *Pool) DetectComputeDiscrepancy() (*block.Header, error) {
	var header, leaderHeader *block.Header
	var discrepancyDetected bool

	for id, ni := range p.NodeInfo {
		n := p.Committee.Members[ni.CommitteeNode]
		if n.Role != scheduler.Worker && n.Role != scheduler.Leader {
			continue
		}

		c, ok := p.Commitments[id]
		if !ok {
			continue
		}

		commit := c.(OpenComputeCommitment)
		if header == nil {
			header = &commit.Body.Header
		}
		if n.Role == scheduler.Leader {
			leaderHeader = &commit.Body.Header
		}
		if !header.MostlyEqual(&commit.Body.Header) {
			discrepancyDetected = true
		}
	}

	if leaderHeader == nil || discrepancyDetected {
		return nil, ErrDiscrepancyDetected
	}

	return leaderHeader, nil
}

// ResolveComputeDiscrepancy performs discrepancy resolution on the current
// compute commitments in the pool.
//
// The caller must verify that there is enough commitments in the pool.
func (p *Pool) ResolveComputeDiscrepancy() (*block.Header, error) {
	type voteEnt struct {
		header *block.Header
		tally  int
	}

	votes := make(map[hash.Hash]*voteEnt)
	var backupNodes int
	for _, n := range p.Committee.Members {
		if n.Role != scheduler.BackupWorker {
			continue
		}
		backupNodes++

		c, ok := p.Commitments[n.PublicKey.ToMapKey()]
		if !ok {
			continue
		}

		commit := c.(OpenComputeCommitment)
		k := commit.Body.Header.EncodedHash()
		if ent, ok := votes[k]; !ok {
			votes[k] = &voteEnt{
				header: &commit.Body.Header,
				tally:  1,
			}
		} else {
			ent.tally++
		}
	}

	minVotes := (backupNodes / 2) + 1
	for _, ent := range votes {
		if ent.tally >= minVotes {
			return ent.header, nil
		}
	}

	return nil, ErrInsufficientVotes
}

// GetCommitteeNode returns a committee node given its public key.
func (p *Pool) GetCommitteeNode(id signature.PublicKey) (*scheduler.CommitteeNode, error) {
	ni, ok := p.NodeInfo[id.ToMapKey()]
	if !ok {
		return nil, ErrNotInCommittee
	}

	return p.Committee.Members[ni.CommitteeNode], nil
}
