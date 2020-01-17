package commitment

import (
	"time"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
)

// moduleName is the module name used for namespacing errors.
const moduleName = "roothash/commitment"

var (
	ErrNoRuntime              = errors.New(moduleName, 1, "roothash/commitment: no runtime configured")
	ErrNoCommittee            = errors.New(moduleName, 2, "roothash/commitment: no committee configured")
	ErrInvalidCommitteeKind   = errors.New(moduleName, 3, "roothash/commitment: invalid committee kind")
	ErrRakSigInvalid          = errors.New(moduleName, 4, "roothash/commitment: batch RAK signature invalid")
	ErrNotInCommittee         = errors.New(moduleName, 5, "roothash/commitment: node not part of committee")
	ErrAlreadyCommitted       = errors.New(moduleName, 6, "roothash/commitment: node already sent commitment")
	ErrNotBasedOnCorrectBlock = errors.New(moduleName, 7, "roothash/commitment: submitted commitment is not based on correct block")
	ErrDiscrepancyDetected    = errors.New(moduleName, 8, "roothash/commitment: discrepancy detected")
	ErrStillWaiting           = errors.New(moduleName, 9, "roothash/commitment: still waiting for commits")
	ErrInsufficientVotes      = errors.New(moduleName, 10, "roothash/commitment: insufficient votes to finalize discrepancy resolution round")
	ErrBadExecutorCommits     = errors.New(moduleName, 11, "roothash/commitment: bad executor commitments")
	ErrInvalidCommitteeID     = errors.New(moduleName, 12, "roothash/commitment: invalid committee ID")
	ErrTxnSchedSigInvalid     = errors.New(moduleName, 13, "roothash/commitment: txn scheduler signature invalid")
	ErrInvalidMessages        = errors.New(moduleName, 14, "roothash/commitment: invalid messages")
)

var logger *logging.Logger = logging.GetLogger("roothash/commitment/pool")

// SignatureVerifier is an interface for verifying storage and transaction
// scheduler signatures against the active committees.
type SignatureVerifier interface {
	// VerifyCommitteeSignatures verifies that the given signatures come from
	// the current committee members of the given kind.
	VerifyCommitteeSignatures(kind scheduler.CommitteeKind, sigs []signature.Signature) error
}

// NodeInfo contains information about a node that is member of a committee.
type NodeInfo struct {
	// CommitteeNode is an index into the Committee.Members structure.
	CommitteeNode int           `json:"committee_node"`
	Runtime       *node.Runtime `json:"runtime"`
}

// Pool is a serializable pool of commitments that can be used to perform
// discrepancy detection.
//
// The pool is not safe for concurrent use.
type Pool struct {
	// Runtime is the runtime descriptor this pool is collecting the
	// commitments for.
	Runtime *registry.Runtime `json:"runtime"`
	// Committee is the committee this pool is collecting the commitments for.
	Committee *scheduler.Committee `json:"committee"`
	// NodeInfo contains node information about committee members.
	NodeInfo map[signature.PublicKey]NodeInfo `json:"node_info"`
	// ExecuteCommitments are the commitments in the pool iff Committee.Kind
	// is scheduler.KindExecutor.
	ExecuteCommitments map[signature.PublicKey]OpenExecutorCommitment `json:"execute_commitments,omitempty"`
	// MergeCommitments are the commitments in the pool iff Committee.Kind
	// is scheduler.KindMerge.
	MergeCommitments map[signature.PublicKey]OpenMergeCommitment `json:"merge_commitments,omitempty"`
	// Discrepancy is a flag signalling that a discrepancy has been detected.
	Discrepancy bool `json:"discrepancy"`
	// NextTimeout is the time when the next call to TryFinalize(true) should
	// be scheduled to be executed. Zero timestamp means that no timeout is
	// to be scheduled.
	NextTimeout time.Time `json:"next_timeout"`
}

// GetCommitteeID returns the identifier of the committee this pool is collecting
// commitments for.
func (p *Pool) GetCommitteeID() hash.Hash {
	return p.Committee.EncodedMembersHash()
}

// ResetCommitments resets the commitments in the pool and clears the discrepancy
// flag.
func (p *Pool) ResetCommitments() {
	if p.ExecuteCommitments == nil || len(p.ExecuteCommitments) > 0 {
		p.ExecuteCommitments = make(map[signature.PublicKey]OpenExecutorCommitment)
	}
	if p.MergeCommitments == nil || len(p.MergeCommitments) > 0 {
		p.MergeCommitments = make(map[signature.PublicKey]OpenMergeCommitment)
	}
	p.Discrepancy = false
	p.NextTimeout = time.Time{}
}

func (p *Pool) getCommitment(id signature.PublicKey) (OpenCommitment, bool) {
	if p.Committee == nil {
		panic("roothash/commitment: query commitements: " + ErrNoCommittee.Error())
	}

	var (
		com OpenCommitment
		ok  bool
	)

	switch p.Committee.Kind {
	case scheduler.KindExecutor:
		com, ok = p.ExecuteCommitments[id]
	case scheduler.KindMerge:
		com, ok = p.MergeCommitments[id]
	default:
		panic("roothash/commitment: unknown committee kind: " + p.Committee.Kind.String())
	}
	return com, ok
}

func (p *Pool) addOpenExecutorCommitment(blk *block.Block, sv SignatureVerifier, openCom *OpenExecutorCommitment) error {
	if p.Committee == nil || p.NodeInfo == nil {
		return ErrNoCommittee
	}
	if p.Committee.Kind != scheduler.KindExecutor {
		return ErrInvalidCommitteeKind
	}

	id := openCom.Signature.PublicKey

	// Ensure that the node is actually a committee member. We do not enforce specific
	// roles based on current discrepancy state to allow commitments arriving in any
	// order (e.g., a backup worker can submit a commitment even before there is a
	// discrepancy).
	if _, ok := p.NodeInfo[id]; !ok {
		return ErrNotInCommittee
	}

	// TODO: Check for signs of double signing (#1804).

	// Ensure the node did not already submit a commitment.
	if _, ok := p.ExecuteCommitments[id]; ok {
		return ErrAlreadyCommitted
	}

	body := openCom.Body
	header := &body.Header

	if p.Runtime == nil {
		return ErrNoRuntime
	}

	// Make sure the commitment does not contain any messages as these are currently
	// not supported and should be rejected.
	if len(header.Messages) > 0 {
		return ErrInvalidMessages
	}

	// Verify RAK-attestation.
	if p.Runtime.TEEHardware != node.TEEHardwareInvalid {
		rak := p.NodeInfo[id].Runtime.Capabilities.TEE.RAK
		if !rak.Verify(ComputeResultsHeaderSignatureContext, cbor.Marshal(header), body.RakSig[:]) {
			return ErrRakSigInvalid
		}
	}

	// Verify that this is for the correct committee.
	cID := p.GetCommitteeID()
	if !cID.Equal(&body.CommitteeID) {
		logger.Debug("executor commitment has invalid committee ID",
			"expected_committee_id", cID,
			"committee_id", body.CommitteeID,
			"node_id", id,
		)
		return ErrInvalidCommitteeID
	}

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&blk.Header) {
		logger.Debug("executor commitment is not based on correct block",
			"committee_id", cID,
			"node_id", id,
			"expected_previous_hash", blk.Header.EncodedHash(),
			"previous_hash", header.PreviousHash,
		)
		return ErrNotBasedOnCorrectBlock
	}

	// Verify that the txn scheduler signature for current commitment is valid.
	currentTxnSchedSig := body.TxnSchedSig
	if err := sv.VerifyCommitteeSignatures(scheduler.KindTransactionScheduler, []signature.Signature{body.TxnSchedSig}); err != nil {
		logger.Debug("executor commitment has bad transaction scheduler signers",
			"committee_id", cID,
			"node_id", id,
			"err", err,
		)
		return err
	}
	if ok := body.VerifyTxnSchedSignature(blk.Header); !ok {
		return ErrTxnSchedSigInvalid
	}

	// Check if the header refers to merkle roots in storage.
	if err := sv.VerifyCommitteeSignatures(scheduler.KindStorage, body.StorageSignatures); err != nil {
		logger.Debug("executor commitment has bad storage receipt signers",
			"committee_id", cID,
			"node_id", id,
			"err", err,
		)
		return err
	}
	if err := body.VerifyStorageReceiptSignatures(blk.Header.Namespace, blk.Header.Round+1); err != nil {
		logger.Debug("executor commitment has bad storage receipt signatures",
			"committee_id", cID,
			"node_id", id,
			"err", err,
		)
		return err
	}

	// Go through existing commitments and check if the txn scheduler signed
	// different batches for the same committee.
	for _, com := range p.ExecuteCommitments {
		cb := com.Body
		if cID.Equal(&cb.CommitteeID) {
			existingTxnSchedSig := cb.TxnSchedSig
			if currentTxnSchedSig.PublicKey.Equal(existingTxnSchedSig.PublicKey) && currentTxnSchedSig.Signature != existingTxnSchedSig.Signature {
				// Same committe, same txn sched, but txn sched signatures
				// don't match -- txn sched is malicious!
				// TODO: Slash stake! (issue #1931)
				logger.Warn("txn sched signed two different batches for the same committee ID",
					"committee_id", cb.CommitteeID,
				)
			}
		}
	}

	if p.ExecuteCommitments == nil {
		p.ExecuteCommitments = make(map[signature.PublicKey]OpenExecutorCommitment)
	}
	p.ExecuteCommitments[id] = *openCom

	return nil
}

// AddExecutorCommitment verifies and adds a new executor commitment to the pool.
func (p *Pool) AddExecutorCommitment(blk *block.Block, sv SignatureVerifier, commitment *ExecutorCommitment) error {
	// Check the commitment signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return err
	}

	return p.addOpenExecutorCommitment(blk, sv, openCom)
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
			check = n.Role == scheduler.Worker
		} else {
			check = n.Role == scheduler.BackupWorker
		}
		if !check {
			continue
		}

		required++
		if _, ok := p.getCommitment(n.PublicKey); ok {
			commits++
		}
	}

	// While a timer is running, all nodes are required to answer.
	//
	// After the timeout has elapsed, a limited number of stragglers
	// are allowed.
	if didTimeout {
		switch p.Committee.Kind {
		case scheduler.KindExecutor:
			required -= int(p.Runtime.Executor.AllowedStragglers)
		case scheduler.KindMerge:
			required -= int(p.Runtime.Merge.AllowedStragglers)
		default:
			panic("roothash/commitment: unknown committee kind while checking commitments: " + p.Committee.Kind.String())
		}
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
func (p *Pool) DetectDiscrepancy() (OpenCommitment, error) {
	if p.Committee == nil {
		return nil, ErrNoCommittee
	}

	var commit OpenCommitment
	var discrepancyDetected bool

	// NOTE: It is very important that the iteration order is deterministic
	//       to ensure that the same commit is chosen on all nodes. This is
	//       because some fields in the commit may not be subject to discrepancy
	//       detection (e.g., storage receipts).
	for _, n := range p.Committee.Members {
		if n.Role != scheduler.Worker {
			continue
		}

		c, ok := p.getCommitment(n.PublicKey)
		if !ok {
			continue
		}

		if commit == nil {
			commit = c
		}
		if !commit.MostlyEqual(c) {
			discrepancyDetected = true
		}
	}

	if commit == nil || discrepancyDetected {
		p.Discrepancy = true
		return nil, ErrDiscrepancyDetected
	}

	return commit, nil
}

// ResolveDiscrepancy performs discrepancy resolution on the current commitments
// in the pool.
//
// The caller must verify that there are enough commitments in the pool.
func (p *Pool) ResolveDiscrepancy() (OpenCommitment, error) {
	if p.Committee == nil {
		return nil, ErrNoCommittee
	}

	type voteEnt struct {
		commit OpenCommitment
		tally  int
	}

	votes := make(map[hash.Hash]*voteEnt)
	var backupNodes int
	for _, n := range p.Committee.Members {
		if n.Role != scheduler.BackupWorker {
			continue
		}
		backupNodes++

		c, ok := p.getCommitment(n.PublicKey)
		if !ok {
			continue
		}

		k := c.ToVote()
		if ent, ok := votes[k]; !ok {
			votes[k] = &voteEnt{
				commit: c,
				tally:  1,
			}
		} else {
			ent.tally++
		}
	}

	minVotes := (backupNodes / 2) + 1
	for _, ent := range votes {
		if ent.tally >= minVotes {
			return ent.commit, nil
		}
	}

	return nil, ErrInsufficientVotes
}

// TryFinalize attempts to finalize the commitments by performing discrepancy
// detection and discrepancy resolution, based on the state of the pool. It may
// request the caller to schedule timeouts by setting NextTimeout appropriately.
//
// If a timeout occurs and isTimeoutAuthoritative is false, the internal
// discrepancy flag will not be changed but the method will still return the
// ErrDiscrepancyDetected error.
func (p *Pool) TryFinalize(
	now time.Time,
	roundTimeout time.Duration,
	didTimeout bool,
	isTimeoutAuthoritative bool,
) (OpenCommitment, error) {
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
			if isTimeoutAuthoritative {
				p.Discrepancy = true
			}
			return nil, ErrDiscrepancyDetected
		}

		// Insufficient commitments for finalization, wait.
		rearmTimer = true
		return nil, err
	}

	// Attempt to finalize, based on the discrepancy flag.
	var commit OpenCommitment
	if !p.Discrepancy {
		// Fast path -- no discrepancy yet, check for one.
		commit, err = p.DetectDiscrepancy()
		if err != nil {
			rearmTimer = true
			return nil, err
		}
	} else {
		// Discrepancy resolution.
		commit, err = p.ResolveDiscrepancy()
		if err != nil {
			return nil, err
		}
	}

	return commit, nil
}

// AddMergeCommitment verifies and adds a new merge commitment to the pool.
//
// Any executor commitments are added to the provided pool.
func (p *Pool) AddMergeCommitment(
	blk *block.Block,
	sv SignatureVerifier,
	commitment *MergeCommitment,
	ccPool *MultiPool,
) error {
	if p.Committee == nil || p.NodeInfo == nil {
		return ErrNoCommittee
	}
	if p.Committee.Kind != scheduler.KindMerge {
		return ErrInvalidCommitteeKind
	}

	id := commitment.Signature.PublicKey

	// Ensure that the node is actually a committee member. We do not enforce specific
	// roles based on current discrepancy state to allow commitments arriving in any
	// order (e.g., a backup worker can submit a commitment even before there is a
	// discrepancy).
	if _, ok := p.NodeInfo[id]; !ok {
		return ErrNotInCommittee
	}

	// Ensure the node did not already submit a commitment.
	if _, ok := p.MergeCommitments[id]; ok {
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
		logger.Debug("merge commitment is not based on correct block",
			"node_id", id,
			"expected_previous_hash", blk.Header.EncodedHash(),
			"previous_hash", header.PreviousHash,
		)
		return ErrNotBasedOnCorrectBlock
	}

	// Check executor commitments -- all commitments must be valid and there
	// must be no discrepancy as the merge committee nodes are supposed to
	// check this.
	if err = ccPool.addExecutorCommitments(blk, sv, body.ExecutorCommits); err != nil {
		return err
	}

	// There must be enough executor commits for all committees.
	if err = ccPool.CheckEnoughCommitments(); err != nil {
		return ErrBadExecutorCommits
	}

	for _, sp := range ccPool.Committees {
		if !sp.Discrepancy {
			// If there was no discrepancy yet there must not be one now.
			_, err = sp.DetectDiscrepancy()
			switch err {
			case nil:
			case ErrDiscrepancyDetected:
				// We may also be able to already perform discrepancy resolution, check if
				// this is possible.
				_, err = sp.ResolveDiscrepancy()
				if err == nil {
					break
				}
				fallthrough
			default:
				logger.Debug("discrepancy detection failed for executor committee",
					"err", err,
				)
				return ErrBadExecutorCommits
			}
		} else {
			// If there was a discrepancy before it must be resolved now.
			_, err = sp.ResolveDiscrepancy()
			if err != nil {
				logger.Debug("discrepancy resolution failed for executor committee",
					"err", err,
				)
				return ErrBadExecutorCommits
			}
		}
	}

	// Check if the header refers to merkle roots in storage.
	if err = sv.VerifyCommitteeSignatures(scheduler.KindStorage, header.StorageSignatures); err != nil {
		logger.Debug("merge commitment has bad storage receipt signers",
			"node_id", id,
			"err", err,
		)
		return err
	}
	if err = header.VerifyStorageReceiptSignatures(); err != nil {
		logger.Debug("merge commitment has bad storage receipt signatures",
			"node_id", id,
			"err", err,
		)
		return err
	}

	if p.MergeCommitments == nil {
		p.MergeCommitments = make(map[signature.PublicKey]OpenMergeCommitment)
	}
	p.MergeCommitments[id] = *openCom

	return nil
}

// GetCommitteeNode returns a committee node given its public key.
func (p *Pool) GetCommitteeNode(id signature.PublicKey) (*scheduler.CommitteeNode, error) {
	ni, ok := p.NodeInfo[id]
	if !ok {
		return nil, ErrNotInCommittee
	}

	return p.Committee.Members[ni.CommitteeNode], nil
}

// GetExecutorCommitments returns a list of executor commitments in the pool.
func (p *Pool) GetExecutorCommitments() (result []ExecutorCommitment) {
	for _, c := range p.ExecuteCommitments {
		result = append(result, c.ExecutorCommitment)
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
	Committees map[hash.Hash]*Pool `json:"committees"`
}

// AddExecutorCommitment verifies and adds a new executor commitment to the pool.
func (m *MultiPool) AddExecutorCommitment(blk *block.Block, sv SignatureVerifier, commitment *ExecutorCommitment) (*Pool, error) {
	// Check the commitment signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return nil, err
	}

	p := m.Committees[openCom.Body.CommitteeID]
	if p == nil {
		return nil, ErrInvalidCommitteeID
	}

	return p, p.addOpenExecutorCommitment(blk, sv, openCom)
}

// addExecutorCommitments verifies and adds multiple executor commitments to the pool.
// All valid commitments will be added, redundant commitments will be ignored.
//
// Note that any signatures being invalid will result in no changes to the pool.
func (m *MultiPool) addExecutorCommitments(blk *block.Block, sv SignatureVerifier, commitments []ExecutorCommitment) error {
	// Batch verify all of the signatures at once.
	msgs := make([][]byte, 0, len(commitments))
	sigs := make([]signature.Signature, 0, len(commitments))
	for i := range commitments {
		v := commitments[i] // This is deliberate.
		msgs = append(msgs, v.Blob)
		sigs = append(sigs, v.Signature)
	}

	if !signature.VerifyBatch(ExecutorSignatureContext, msgs, sigs) {
		return signature.ErrVerifyFailed
	}

	// Ok, all of the signatures are valid, deserialize the blobs and add them
	// serially.
	var hadError bool
	for _, v := range commitments {
		var body ComputeBody
		if err := cbor.Unmarshal(v.Blob, &body); err != nil {
			hadError = true
			continue
		}

		openCom := &OpenExecutorCommitment{
			ExecutorCommitment: v,
			Body:               &body,
		}

		p := m.Committees[openCom.Body.CommitteeID]
		if p == nil {
			hadError = true
			continue
		}

		err := p.addOpenExecutorCommitment(blk, sv, openCom)
		switch err {
		case nil, ErrAlreadyCommitted:
		default:
			hadError = true
		}
	}
	if hadError {
		return ErrBadExecutorCommits
	}

	return nil
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

// GetExecutorCommitments returns a list of executor commitments in the pool.
func (m *MultiPool) GetExecutorCommitments() (result []ExecutorCommitment) {
	for _, p := range m.Committees {
		for _, c := range p.ExecuteCommitments {
			result = append(result, c.ExecutorCommitment)
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
