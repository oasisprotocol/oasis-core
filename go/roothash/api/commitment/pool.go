package commitment

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
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
	ErrTxnSchedSigInvalid     = p2pError.Permanent(errors.New(moduleName, 12, "roothash/commitment: txn scheduler signature invalid"))
	ErrInvalidMessages        = p2pError.Permanent(errors.New(moduleName, 13, "roothash/commitment: invalid messages"))
	ErrBadStorageReceipts     = errors.New(moduleName, 14, "roothash/commitment: bad storage receipts")
	ErrTimeoutNotCorrectRound = errors.New(moduleName, 15, "roothash/commitment: timeout not for correct round")
	ErrNodeIsScheduler        = errors.New(moduleName, 16, "roothash/commitment: node is scheduler")
)

const (
	// TimeoutNever is the timeout value that never expires.
	TimeoutNever = 0

	// Backup worker round timeout stretch factor (15/10 = 1.5).
	backupWorkerTimeoutFactorNumerator   = 15
	backupWorkerTimeoutFactorDenominator = 10
)

var logger *logging.Logger = logging.GetLogger("roothash/commitment/pool")

// SignatureVerifier is an interface for verifying storage and transaction
// scheduler signatures against the active committees.
type SignatureVerifier interface {
	// VerifyCommitteeSignatures verifies that the given signatures come from
	// the current committee members of the given kind.
	VerifyCommitteeSignatures(kind scheduler.CommitteeKind, sigs []signature.Signature) error

	// VerifyTxnSchedulerSignature verifies that the given signatures come from
	// the transaction scheduler at provided round.
	VerifyTxnSchedulerSignature(sig signature.Signature, round uint64) error
}

// NodeLookup is an interface for looking up registry node descriptors.
type NodeLookup interface {
	// Node looks up a node descriptor.
	Node(ctx context.Context, id signature.PublicKey) (*node.Node, error)
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
	// ExecuteCommitments are the commitments in the pool iff Committee.Kind
	// is scheduler.KindComputeExecutor.
	ExecuteCommitments map[signature.PublicKey]OpenExecutorCommitment `json:"execute_commitments,omitempty"`
	// Discrepancy is a flag signalling that a discrepancy has been detected.
	Discrepancy bool `json:"discrepancy"`
	// NextTimeout is the time when the next call to TryFinalize(true) should
	// be scheduled to be executed. Zero means that no timeout is to be scheduled.
	NextTimeout int64 `json:"next_timeout"`

	// memberSet is a cached committee member set. It will be automatically
	// constructed based on the passed Committee.
	memberSet map[signature.PublicKey]bool

	// workerSet is a cached committee worker set. It will be automatically
	// constructed based on the passed Committee.
	workerSet map[signature.PublicKey]bool
}

func (p *Pool) computeMemberSets() {
	if p.Committee == nil {
		return
	}

	p.memberSet = make(map[signature.PublicKey]bool, len(p.Committee.Members))
	p.workerSet = make(map[signature.PublicKey]bool)
	for _, m := range p.Committee.Members {
		p.memberSet[m.PublicKey] = true
		if m.Role == scheduler.RoleWorker {
			p.workerSet[m.PublicKey] = true
		}
	}
}

func (p *Pool) isMember(id signature.PublicKey) bool {
	if p.Committee == nil {
		return false
	}

	if len(p.memberSet) == 0 {
		p.computeMemberSets()
	}

	return p.memberSet[id]
}

func (p *Pool) isWorker(id signature.PublicKey) bool {
	if p.Committee == nil {
		return false
	}

	if len(p.workerSet) == 0 {
		p.computeMemberSets()
	}

	return p.workerSet[id]
}

func (p *Pool) isScheduler(id signature.PublicKey, round uint64) bool {
	if p.Committee == nil {
		return false
	}
	scheduler, err := GetTransactionScheduler(p.Committee, round)
	if err != nil {
		return false
	}

	return scheduler.PublicKey.Equal(id)
}

// ResetCommitments resets the commitments in the pool, clears the discrepancy flag and the next
// timeout height.
func (p *Pool) ResetCommitments() {
	if p.ExecuteCommitments == nil || len(p.ExecuteCommitments) > 0 {
		p.ExecuteCommitments = make(map[signature.PublicKey]OpenExecutorCommitment)
	}
	p.Discrepancy = false
	p.NextTimeout = TimeoutNever
}

func (p *Pool) getCommitment(id signature.PublicKey) (OpenCommitment, bool) {
	if p.Committee == nil {
		panic("roothash/commitment: query commitments: " + ErrNoCommittee.Error())
	}

	var (
		com OpenCommitment
		ok  bool
	)

	switch p.Committee.Kind {
	case scheduler.KindComputeExecutor:
		com, ok = p.ExecuteCommitments[id]
	default:
		panic("roothash/commitment: unknown committee kind: " + p.Committee.Kind.String())
	}
	return com, ok
}

func (p *Pool) addOpenExecutorCommitment(
	ctx context.Context,
	blk *block.Block,
	sv SignatureVerifier,
	nl NodeLookup,
	openCom *OpenExecutorCommitment,
) error {
	if p.Committee == nil {
		return ErrNoCommittee
	}
	if p.Committee.Kind != scheduler.KindComputeExecutor {
		return ErrInvalidCommitteeKind
	}

	id := openCom.Signature.PublicKey

	// Ensure that the node is actually a committee member. We do not enforce specific
	// roles based on current discrepancy state to allow commitments arriving in any
	// order (e.g., a backup worker can submit a commitment even before there is a
	// discrepancy).
	if !p.isMember(id) {
		return ErrNotInCommittee
	}

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

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&blk.Header) {
		logger.Debug("executor commitment is not based on correct block",
			"node_id", id,
			"expected_previous_hash", blk.Header.EncodedHash(),
			"previous_hash", header.PreviousHash,
		)
		return ErrNotBasedOnCorrectBlock
	}

	// Verify RAK-attestation.
	if p.Runtime.TEEHardware != node.TEEHardwareInvalid {
		n, err := nl.Node(ctx, id)
		if err != nil {
			// This should never happen as nodes cannot disappear mid-epoch.
			logger.Warn("unable to fetch node descriptor to verify RAK-attestation",
				"err", err,
				"node_id", id,
			)
			return ErrNotInCommittee
		}

		rt := n.GetRuntime(p.Runtime.ID)
		if rt == nil {
			// We currently prevent this case throughout the rest of the system.
			// Still, it's prudent to check.
			logger.Warn("committee member not registered with this runtime",
				"runtime_id", p.Runtime.ID,
				"node_id", id,
			)
			return ErrNotInCommittee
		}

		rak := rt.Capabilities.TEE.RAK
		if !rak.Verify(ComputeResultsHeaderSignatureContext, cbor.Marshal(header), body.RakSig[:]) {
			return ErrRakSigInvalid
		}
	}

	if err := sv.VerifyTxnSchedulerSignature(body.TxnSchedSig, blk.Header.Round); err != nil {
		logger.Debug("executor commitment has bad transaction scheduler signer",
			"node_id", id,
			"round", blk.Header.Round,
			"err", err,
		)
		return err
	}
	if ok := body.VerifyTxnSchedSignature(blk.Header); !ok {
		return ErrTxnSchedSigInvalid
	}

	// Check if the header refers to merkle roots in storage.
	if uint64(len(body.StorageSignatures)) < p.Runtime.Storage.MinWriteReplication {
		logger.Debug("executor commitment doesn't have enough storage receipts",
			"node_id", id,
			"min_write_replication", p.Runtime.Storage.MinWriteReplication,
			"num_receipts", len(body.StorageSignatures),
		)
		return ErrBadStorageReceipts
	}
	if err := sv.VerifyCommitteeSignatures(scheduler.KindStorage, body.StorageSignatures); err != nil {
		logger.Debug("executor commitment has bad storage receipt signers",
			"node_id", id,
			"err", err,
		)
		return err
	}
	if err := body.VerifyStorageReceiptSignatures(blk.Header.Namespace); err != nil {
		logger.Debug("executor commitment has bad storage receipt signatures",
			"node_id", id,
			"err", err,
		)
		return p2pError.Permanent(err)
	}

	if p.ExecuteCommitments == nil {
		p.ExecuteCommitments = make(map[signature.PublicKey]OpenExecutorCommitment)
	}
	p.ExecuteCommitments[id] = *openCom

	return nil
}

// AddExecutorCommitment verifies and adds a new executor commitment to the pool.
func (p *Pool) AddExecutorCommitment(
	ctx context.Context,
	blk *block.Block,
	sv SignatureVerifier,
	nl NodeLookup,
	commitment *ExecutorCommitment,
) error {
	// Check the commitment signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return p2pError.Permanent(err)
	}

	return p.addOpenExecutorCommitment(ctx, blk, sv, nl, openCom)
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
			check = n.Role == scheduler.RoleWorker
		} else {
			check = n.Role == scheduler.RoleBackupWorker
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
		case scheduler.KindComputeExecutor:
			required -= int(p.Runtime.Executor.AllowedStragglers)
		default:
			panic("roothash/commitment: unknown committee kind while checking commitments: " + p.Committee.Kind.String())
		}
	}

	if commits < required {
		return ErrStillWaiting
	}

	return nil
}

// CheckProposerTimeout verifies executor timeout request conditions.
func (p *Pool) CheckProposerTimeout(
	ctx context.Context,
	block *block.Block,
	sv SignatureVerifier,
	nl NodeLookup,
	id signature.PublicKey,
	round uint64,
) error {
	if p.Committee == nil {
		return ErrNoCommittee
	}
	if p.Committee.Kind != scheduler.KindComputeExecutor {
		return ErrInvalidCommitteeKind
	}

	// Ensure timeout is for correct round.
	if round != block.Header.Round {
		return ErrTimeoutNotCorrectRound
	}

	// Ensure there is no commitments yet.
	if len(p.ExecuteCommitments) != 0 {
		return ErrAlreadyCommitted
	}

	// Ensure that the node that is requesting a timeout is actually a committee
	// worker.
	if !p.isWorker(id) {
		return ErrNotInCommittee
	}

	// Ensure that the node requesting a timeout is not the scheduler for
	// current round.
	if p.isScheduler(id, block.Header.Round) {
		return ErrNodeIsScheduler
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
		if n.Role != scheduler.RoleWorker {
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
		if n.Role != scheduler.RoleBackupWorker {
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
	height int64,
	roundTimeout int64,
	didTimeout bool,
	isTimeoutAuthoritative bool,
) (OpenCommitment, error) {
	var err error
	var rearmTimer bool
	defer func() {
		if rearmTimer {
			p.NextTimeout = height + roundTimeout
		} else {
			p.NextTimeout = TimeoutNever
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
				// Arm the timer, but increase the roundTimeout as the backup workers should be
				// given some more time to do the computation.
				rearmTimer = true
				roundTimeout = (backupWorkerTimeoutFactorNumerator * roundTimeout) / backupWorkerTimeoutFactorDenominator
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

// GetExecutorCommitments returns a list of executor commitments in the pool.
func (p *Pool) GetExecutorCommitments() (result []ExecutorCommitment) {
	for _, c := range p.ExecuteCommitments {
		result = append(result, c.ExecutorCommitment)
	}
	return
}

// IsTimeout returns true if the time is up for pool's TryFinalize to be called.
func (p *Pool) IsTimeout(height int64) bool {
	return p.NextTimeout != TimeoutNever && height >= p.NextTimeout
}
