package commitment

import (
	"errors"
	"fmt"
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
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
	ErrNotBasedOnCorrectBlock = errors.New("roothash/commitment: submitted commitment is not based on correct block")
	ErrDiscrepancyDetected    = errors.New("roothash/commitment: discrepancy detected")
	ErrStillWaiting           = errors.New("roothash/commitment: still waiting for commits")
	ErrInsufficientVotes      = errors.New("roothash/commitment: insufficient votes to finalize discrepancy resolution round")
	ErrBadComputeCommits      = errors.New("roothash/commitment: bad compute commitments")
	ErrInvalidCommitteeID     = errors.New("roothash/commitment: invalid committee ID")
)

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
	// The type of conrete commitments depends on Committee.Kind and all
	// commitments in the pool MUST be of the same type.
	Commitments map[signature.MapKey]OpenCommitment `codec:"commitments"`
	// Discrepancy is a flag signalling that a discrepancy has been detected.
	Discrepancy bool `codec:"discrepancy"`
	// NextTimeout is the time when the next call to TryFinalize(true) should
	// be scheduled to be executed. Zero timestamp means that no timeout is
	// to be scheduled.
	NextTimeout time.Time `codec:"next_timeout"`
}

// GetCommitteeID returns the identifier of the committee this pool is collecting
// commitments for.
func (p *Pool) GetCommitteeID() hash.Hash {
	return p.Committee.EncodedMembersHash()
}

// ResetCommitments resets the commitments in the pool and clears the discrepancy
// flag.
func (p *Pool) ResetCommitments() {
	if p.Commitments == nil || len(p.Commitments) > 0 {
		p.Commitments = make(map[signature.MapKey]OpenCommitment)
	}
	p.Discrepancy = false
	p.NextTimeout = time.Time{}
}

func (p *Pool) addOpenComputeCommitment(blk *block.Block, openCom *OpenComputeCommitment) error {
	if p.Committee == nil || p.NodeInfo == nil {
		return ErrNoCommittee
	}
	if p.Committee.Kind != scheduler.KindCompute {
		return ErrInvalidCommitteeKind
	}

	id := openCom.Signature.PublicKey.ToMapKey()

	// Ensure that the node is actually a committee member. We do not enforce specific
	// roles based on current discrepancy state to allow commitments arriving in any
	// order (e.g., a backup worker can submit a commitment even before there is a
	// discrepancy).
	if _, ok := p.NodeInfo[id]; !ok {
		return ErrNotInCommittee
	}

	// Ensure the node did not already submit a commitment.
	if _, ok := p.Commitments[id]; ok {
		return ErrAlreadyCommitted
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
		if !rak.Verify(RakSigContext, cbor.Marshal(batchSigMessage), body.RakSig[:]) {
			return ErrRakSigInvalid
		}
	}

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&blk.Header) {
		return ErrNotBasedOnCorrectBlock
	}

	// Verify that this is for the correct committee.
	cID := p.GetCommitteeID()
	if !cID.Equal(&body.CommitteeID) {
		return ErrInvalidCommitteeID
	}

	// Check if the header refers to hashes in storage.
	// TODO: Actually check that the storage receipt was signed by a storage node.
	if err := header.VerifyStorageReceiptSignature(); err != nil {
		return err
	}

	if p.Commitments == nil {
		p.Commitments = make(map[signature.MapKey]OpenCommitment)
	}
	p.Commitments[id] = *openCom

	return nil
}

// AddComputeCommitment verifies and adds a new compute commitment to the pool.
func (p *Pool) AddComputeCommitment(blk *block.Block, commitment *ComputeCommitment) error {
	// Check the commitment signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return err
	}

	return p.addOpenComputeCommitment(blk, openCom)
}

// CheckEnoughCommitments checks if there are enough commitments in the pool to be
// able to perform discrepancy detection.
func (p *Pool) CheckEnoughCommitments(didTimeout bool) error {
	if p.Committee == nil {
		return ErrNoCommittee
	}

	var commits, required int
	for _, n := range p.Committee.Members {
		var check bool
		if !p.Discrepancy {
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

// DetectDiscrepancy performs discrepancy detection on the current commitments in
// the pool.
//
// The caller must verify that there are enough commitments in the pool.
func (p *Pool) DetectDiscrepancy() (*block.Header, error) {
	var header *block.Header
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

		var h *block.Header
		switch p.Committee.Kind {
		case scheduler.KindCompute:
			h = &c.(OpenComputeCommitment).Body.Header
		case scheduler.KindMerge:
			h = &c.(OpenMergeCommitment).Body.Header
		default:
			panic(fmt.Sprintf("roothash/commitment: unsupported committee type: %s", p.Committee.Kind))
		}

		if header == nil {
			header = h
		}
		if !header.MostlyEqual(h) {
			discrepancyDetected = true
		}
	}

	if header == nil || discrepancyDetected {
		p.Discrepancy = true
		return nil, ErrDiscrepancyDetected
	}

	return header, nil
}

// ResolveDiscrepancy performs discrepancy resolution on the current commitments
// in the pool.
//
// The caller must verify that there are enough commitments in the pool.
func (p *Pool) ResolveDiscrepancy() (*block.Header, error) {
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

		var header *block.Header
		switch p.Committee.Kind {
		case scheduler.KindCompute:
			header = &c.(OpenComputeCommitment).Body.Header
		case scheduler.KindMerge:
			header = &c.(OpenMergeCommitment).Body.Header
		default:
			panic(fmt.Sprintf("roothash/commitment: unsupported committee type: %s", p.Committee.Kind))
		}

		k := header.EncodedHash()
		if ent, ok := votes[k]; !ok {
			votes[k] = &voteEnt{
				header: header,
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

// TryFinalize attempts to finalize the commitments by performing discrepancy
// detection and discrepancy resolution, based on the state of the pool. It may
// request the caller to schedule timeouts by setting NextTimeout appropriately.
func (p *Pool) TryFinalize(now time.Time, roundTimeout time.Duration, didTimeout bool) (*block.Header, error) {
	var err error
	var rearmTimer bool
	defer func() {
		if rearmTimer {
			// All timeouts are rounded to nearest second to ensure stable serialization.
			p.NextTimeout = now.Add(roundTimeout).Round(time.Second)
		} else {
			p.NextTimeout = time.Time{}
		}
	}()

	// Ensure that the required number of commitments are present.
	if err = p.CheckEnoughCommitments(didTimeout); err != nil {
		if err != ErrStillWaiting {
			return nil, err
		}

		if didTimeout {
			if p.Discrepancy {
				// This was a forced finalization call due to timeout,
				// and the round was in the discrepancy state.  Give up.
				return nil, ErrInsufficientVotes
			}

			// This is the fast path and the round timer expired.
			//
			// Transition to the discrepancy state so the backup workers
			// process the round, assuming that it is possible to do so.
			p.Discrepancy = true
			return nil, ErrDiscrepancyDetected
		}

		// Insufficient commitments for finalization, wait.
		rearmTimer = true
		return nil, err
	}

	// Attempt to finalize, based on the discrepancy flag.
	var header *block.Header
	if !p.Discrepancy {
		// Fast path -- no discrepancy yet, check for one.
		header, err = p.DetectDiscrepancy()
		if err != nil {
			rearmTimer = true
			return nil, err
		}
	} else {
		// Discrepancy resolution.
		header, err = p.ResolveDiscrepancy()
		if err != nil {
			return nil, err
		}
	}

	return header, nil
}

// AddMergeCommitment verifies and adds a new merge commitment to the pool.
//
// Any compute commitments are added to the provided pool.
func (p *Pool) AddMergeCommitment(
	blk *block.Block,
	commitment *MergeCommitment,
	ccPool *MultiPool,
) error {
	if p.Committee == nil || p.NodeInfo == nil {
		return ErrNoCommittee
	}
	if p.Committee.Kind != scheduler.KindMerge {
		return ErrInvalidCommitteeKind
	}

	id := commitment.Signature.PublicKey.ToMapKey()

	// Ensure that the node is actually a committee member. We do not enforce specific
	// roles based on current discrepancy state to allow commitments arriving in any
	// order (e.g., a backup worker can submit a commitment even before there is a
	// discrepancy).
	if _, ok := p.NodeInfo[id]; !ok {
		return ErrNotInCommittee
	}

	// Ensure the node did not already submit a commitment.
	if _, ok := p.Commitments[id]; ok {
		return ErrAlreadyCommitted
	}

	// Check the commitment signature and de-serialize.
	openCom, err := commitment.Open()
	if err != nil {
		return err
	}
	body := openCom.Body
	header := &body.Header

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&blk.Header) {
		return ErrNotBasedOnCorrectBlock
	}

	// Check compute commitments -- all commitments must be valid and there
	// must be no discrepancy as the merge committee nodes are supposed to
	// check this.
	var hasError bool
	for _, cc := range body.ComputeCommits {
		_, err = ccPool.AddComputeCommitment(blk, &cc)
		switch err {
		case nil:
		case ErrAlreadyCommitted:
			// Ignore duplicate commitments.
			continue
		default:
			// Only set a flag so that we add all valid compute commitments
			// to the compute committment pool.
			hasError = true
		}
	}
	if hasError {
		return ErrBadComputeCommits
	}

	// There must be enough compute commits for all committees.
	if err = ccPool.CheckEnoughCommitments(); err != nil {
		return ErrBadComputeCommits
	}

	for _, sp := range ccPool.Committees {
		if !sp.Discrepancy {
			// If there was no discrepancy yet there must not be one now.
			_, err = sp.DetectDiscrepancy()
			if err != nil {
				return ErrBadComputeCommits
			}
		} else {
			// If there was a discrepancy before it must be resolved now.
			_, err = sp.ResolveDiscrepancy()
			if err != nil {
				return ErrBadComputeCommits
			}
		}
	}

	// Check if the header refers to hashes in storage.
	// TODO: Actually check that the storage receipt was signed by a storage node.
	if err = header.VerifyStorageReceiptSignature(); err != nil {
		return err
	}

	if p.Commitments == nil {
		p.Commitments = make(map[signature.MapKey]OpenCommitment)
	}
	p.Commitments[id] = *openCom

	return nil
}

// GetCommitteeNode returns a committee node given its public key.
func (p *Pool) GetCommitteeNode(id signature.PublicKey) (*scheduler.CommitteeNode, error) {
	ni, ok := p.NodeInfo[id.ToMapKey()]
	if !ok {
		return nil, ErrNotInCommittee
	}

	return p.Committee.Members[ni.CommitteeNode], nil
}

// GetComputeCommitments returns a list of compute commitments in the pool.
//
// Panics if the pool contains non-compute commitments.
func (p *Pool) GetComputeCommitments() (result []ComputeCommitment) {
	for _, c := range p.Commitments {
		commit := c.(OpenComputeCommitment)
		result = append(result, commit.ComputeCommitment)
	}
	return
}

// IsTimeout returns true if the time is up for pool's TryFinalize to be called.
func (p *Pool) IsTimeout(now time.Time) bool {
	return !p.NextTimeout.IsZero() && !p.NextTimeout.After(now)
}

// MultiPool contains pools for multiple committees and routes operations to
// multiple committees based on commitments' committee IDs.
type MultiPool struct {
	Committees map[hash.Hash]*Pool `codec:"committees"`
}

// AddComputeCommitment verifies and adds a new compute commitment to the pool.
func (m *MultiPool) AddComputeCommitment(blk *block.Block, commitment *ComputeCommitment) (*Pool, error) {
	// Check the commitment signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return nil, err
	}

	p := m.Committees[openCom.Body.CommitteeID]
	if p == nil {
		return nil, ErrInvalidCommitteeID
	}

	return p, p.addOpenComputeCommitment(blk, openCom)
}

// CheckEnoughCommitments checks if there are enough commitments in the pool to be
// able to perform discrepancy detection.
//
// Note that this checks all committees in the multi-pool and returns an error if
// any doesn't have enoguh commitments.
func (m *MultiPool) CheckEnoughCommitments() error {
	for _, p := range m.Committees {
		if err := p.CheckEnoughCommitments(false); err != nil {
			return err
		}
	}
	return nil
}

// GetComputeCommitments returns a list of compute commitments in the pool.
//
// Panics if the pool contains non-compute commitments.
func (m *MultiPool) GetComputeCommitments() (result []ComputeCommitment) {
	for _, p := range m.Committees {
		for _, c := range p.Commitments {
			commit := c.(OpenComputeCommitment)
			result = append(result, commit.ComputeCommitment)
		}
	}
	return
}

// GetTimeoutCommittees returns a list of committee pools that are up for their
// TryFinalize to be called.
func (m *MultiPool) GetTimeoutCommittees(now time.Time) (result []*Pool) {
	for _, p := range m.Committees {
		if p.IsTimeout(now) {
			result = append(result, p)
		}
	}
	return
}

// GetNextTimeout returns the minimum next timeout of all committee pools.
func (m *MultiPool) GetNextTimeout() (timeout time.Time) {
	for _, p := range m.Committees {
		if timeout.IsZero() || (!p.NextTimeout.IsZero() && p.NextTimeout.Before(timeout)) {
			timeout = p.NextTimeout
		}
	}
	return
}

// ResetCommitments resets the commitments in the pool and clears their discrepancy
// flags.
func (m *MultiPool) ResetCommitments() {
	for _, p := range m.Committees {
		p.ResetCommitments()
	}
}
