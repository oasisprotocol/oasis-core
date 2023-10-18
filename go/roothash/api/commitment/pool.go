package commitment

import (
	"context"
	"math"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	p2pError "github.com/oasisprotocol/oasis-core/go/p2p/error"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// moduleName is the module name used for namespacing errors.
const moduleName = "roothash/commitment"

// nolint: revive
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
	ErrBadExecutorCommitment  = errors.New(moduleName, 11, "roothash/commitment: bad executor commitment")
	// Error code 12 is reserved for future use.
	ErrInvalidMessages = p2pError.Permanent(errors.New(moduleName, 13, "roothash/commitment: invalid messages"))
	// Error code 14 is reserved for future use.
	ErrTimeoutNotCorrectRound = errors.New(moduleName, 15, "roothash/commitment: timeout not for correct round")
	ErrInvalidRound           = errors.New(moduleName, 16, "roothash/commitment: invalid round")
	ErrNoSchedulerCommitment  = errors.New(moduleName, 17, "roothash/commitment: no scheduler commitment")
	ErrBadSchedulerCommitment = errors.New(moduleName, 18, "roothash/commitment: bad scheduler commitment")
)

// LogEventDiscrepancyMajorityFailure is a log event value that dependency resolution with majority failure.
const LogEventDiscrepancyMajorityFailure = "pool/discrepancy_majority_failure"

var logger *logging.Logger = logging.GetLogger("roothash/commitment/pool")

// NodeLookup is an interface for looking up registry node descriptors.
type NodeLookup interface {
	// Node looks up a node descriptor.
	Node(ctx context.Context, id signature.PublicKey) (*node.Node, error)
}

// MessageValidator is an arbitrary function that validates messages for validity. It can be used
// for gas accounting.
type MessageValidator func(msgs []message.Message) error

// Pool is a serializable pool of scheduler commitments that can be used to perform discrepancy
// detection and resolution.
//
// The pool is not safe for concurrent use.
type Pool struct {
	// HighestRank is the rank of the highest-ranked scheduler among those who have submitted
	// a commitment for their own proposal. The maximum value indicates that no scheduler
	// has submitted a commitment.
	HighestRank uint64 `json:"highest_rank,omitempty"`
	// SchedulerCommitments is a map that groups scheduler commitments and worker votes
	// by the scheduler's rank.
	SchedulerCommitments map[uint64]*SchedulerCommitment `json:"scheduler_commitments,omitempty"`
	// Discrepancy is a flag signalling that a discrepancy has been detected.
	Discrepancy bool `json:"discrepancy,omitempty"`
}

// NewPool creates a new pool without any commitments and with .
func NewPool() *Pool {
	return &Pool{
		HighestRank: math.MaxUint64,
	}
}

// VerifyExecutorCommitment verifies the given executor commitment.
func VerifyExecutorCommitment( // nolint: gocyclo
	ctx context.Context,
	blk *block.Block,
	rt *registry.Runtime,
	epoch beacon.EpochTime,
	commit *ExecutorCommitment,
	msgValidator MessageValidator,
	nl NodeLookup,
) error {
	// Check executor commitment signature.
	if err := commit.Verify(rt.ID); err != nil {
		return p2pError.Permanent(err)
	}

	// Validate executor commitment.
	if err := commit.ValidateBasic(); err != nil {
		logger.Debug("executor commitment validate basic error",
			"err", err,
		)
		return ErrBadExecutorCommitment
	}

	// Check if the block is based on the previous block.
	if !commit.Header.Header.IsParentOf(&blk.Header) {
		logger.Debug("executor commitment is not based on correct block",
			"node_id", commit.NodeID,
			"expected_previous_hash", blk.Header.EncodedHash(),
			"previous_hash", commit.Header.Header.PreviousHash,
		)
		return ErrNotBasedOnCorrectBlock
	}

	// TODO: Check for evidence of equivocation (oasis-core#3685).

	switch commit.IsIndicatingFailure() {
	case true:
		// Prevent schedulers to submit failures.
		if commit.NodeID.Equal(commit.Header.SchedulerID) {
			logger.Debug("executor commitment scheduler is not allowed to submit a failure",
				"node_id", commit.NodeID,
			)
			return ErrBadExecutorCommitment
		}
	case false:
		// Verify RAK-attestation.
		if rt.TEEHardware != node.TEEHardwareInvalid {
			n, err := nl.Node(ctx, commit.NodeID)
			if err != nil {
				// This should never happen as nodes cannot disappear mid-epoch.
				logger.Warn("unable to fetch node descriptor to verify RAK-attestation",
					"err", err,
					"node_id", commit.NodeID,
				)
				return ErrNotInCommittee
			}

			ad := rt.ActiveDeployment(epoch)
			if ad == nil {
				// This should never happen as we prevent this elsewhere.
				logger.Error("no active deployment",
					"runtime_id", rt.ID,
					"node_id", commit.NodeID,
					"deployments", rt.Deployments,
				)
				return ErrNoRuntime
			}

			nodeRt := n.GetRuntime(rt.ID, ad.Version)
			if nodeRt == nil {
				// We currently prevent this case throughout the rest of the system.
				// Still, it's prudent to check.
				logger.Warn("committee member not registered with this runtime",
					"runtime_id", rt.ID,
					"node_id", commit.NodeID,
				)
				return ErrNotInCommittee
			}

			if nodeRt.Capabilities.TEE == nil {
				// This should never happen as we prevent this elsewhere.
				logger.Error("node doesn't have TEE capability",
					"runtime_id", rt.ID,
					"node_id", commit.NodeID,
				)
				return ErrRakSigInvalid
			}

			if err = commit.Header.VerifyRAK(nodeRt.Capabilities.TEE.RAK); err != nil {
				return ErrRakSigInvalid
			}
		}

		// Check emitted runtime messages.
		switch commit.NodeID.Equal(commit.Header.SchedulerID) {
		case true:
			// The transaction scheduler can include messages.
			if uint32(len(commit.Messages)) > rt.Executor.MaxMessages {
				logger.Debug("executor commitment from scheduler has too many messages",
					"node_id", commit.NodeID,
					"num_messages", len(commit.Messages),
					"max_messages", rt.Executor.MaxMessages,
				)
				return ErrInvalidMessages
			}
			if h := message.MessagesHash(commit.Messages); !h.Equal(commit.Header.Header.MessagesHash) {
				logger.Debug("executor commitment from scheduler has invalid messages hash",
					"node_id", commit.NodeID,
					"expected_hash", h,
					"messages_hash", commit.Header.Header.MessagesHash,
				)
				return ErrInvalidMessages
			}

			// Perform custom message validation and propagate the error unchanged.
			if msgValidator != nil && len(commit.Messages) > 0 {
				err := msgValidator(commit.Messages)
				if err != nil {
					logger.Debug("executor commitment from scheduler has invalid messages",
						"err", err,
						"node_id", commit.NodeID,
					)
					return err
				}
			}
		case false:
			// Other workers cannot include any messages.
			if len(commit.Messages) > 0 {
				logger.Debug("executor commitment from non-scheduler contains messages",
					"node_id", commit.NodeID,
					"num_messages", len(commit.Messages),
				)
				return ErrInvalidMessages
			}
		}
	}

	return nil
}

// AddVerifiedExecutorCommitment adds a verified executor commitment to the pool.
func (p *Pool) AddVerifiedExecutorCommitment(c *scheduler.Committee, ec *ExecutorCommitment) error {
	// Enforce specific roles based on current discrepancy state.
	switch {
	case !p.Discrepancy && !c.IsMember(ec.NodeID):
		// Discrepancy detection accepts commitments arriving in any order, e.g., a backup worker
		// can submit a commitment even before there is a discrepancy.
		logger.Debug("node is not in the committee",
			"round", ec.Header.Header.Round,
			"node_id", ec.NodeID,
		)
		return ErrNotInCommittee
	case p.Discrepancy && !c.IsBackupWorker(ec.NodeID):
		// Discrepancy resolution accepts commitments only from backup workers to prevent workers
		// from improving their liveness statistics.
		logger.Debug("node is not a backup worker",
			"round", ec.Header.Header.Round,
			"node_id", ec.NodeID,
		)
		return ErrBadExecutorCommitment
	}

	// Ensure that the scheduler is allowed to schedule transactions.
	rank, ok := c.SchedulerRank(ec.Header.Header.Round, ec.Header.SchedulerID)
	if !ok {
		// Reject commitments with invalid schedulers.
		logger.Debug("executor commitment's scheduler is not in the committee",
			"round", ec.Header.Header.Round,
			"node_id", ec.NodeID,
			"scheduler_id", ec.Header.SchedulerID,
			"rank", rank,
		)
		return ErrBadExecutorCommitment
	}

	// Prioritize commitments.
	switch {
	case rank > p.HighestRank:
		// Reject commitments with higher ranking.
		logger.Debug("executor commitment's scheduler has worse ranking",
			"round", ec.Header.Header.Round,
			"node_id", ec.NodeID,
			"scheduler_id", ec.Header.SchedulerID,
			"rank", rank,
			"highest_rank", p.HighestRank,
		)
		return ErrBadExecutorCommitment
	case rank != p.HighestRank && p.Discrepancy:
		// Prevent placing commitments with different rank during discrepancy resolution.
		logger.Debug("executor commitment's scheduler rank does not match",
			"round", ec.Header.Header.Round,
			"node_id", ec.NodeID,
			"scheduler_id", ec.Header.SchedulerID,
			"rank", rank,
			"highest_rank", p.HighestRank,
		)
		return ErrBadExecutorCommitment
	case rank < p.HighestRank:
		// Update the pool when a scheduler with a superior rank commits.
		if !ec.NodeID.Equal(ec.Header.SchedulerID) {
			break
		}

		p.HighestRank = rank

		// Drop commitments with higher ranking.
		for r := range p.SchedulerCommitments {
			if r > p.HighestRank {
				delete(p.SchedulerCommitments, r)
			}
		}
	}

	// Add commitment if the node hasn't submitted one.
	if p.SchedulerCommitments == nil {
		p.SchedulerCommitments = make(map[uint64]*SchedulerCommitment)
	}
	sc, ok := p.SchedulerCommitments[rank]
	if !ok {
		sc = &SchedulerCommitment{}
		p.SchedulerCommitments[rank] = sc
	}

	return sc.Add(ec)
}

// ProcessCommitments performs discrepancy detection or resolution.
func (p *Pool) ProcessCommitments(c *scheduler.Committee, allowedStragglers uint16, timeout bool) (*SchedulerCommitment, error) {
	sc, err := p.processCommitments(c, allowedStragglers, timeout)
	switch err {
	case ErrDiscrepancyDetected:
		// Switch to discrepancy resolution.
		p.Discrepancy = true

		// Drop commitments with different ranking.
		for r := range p.SchedulerCommitments {
			if r != p.HighestRank {
				delete(p.SchedulerCommitments, r)
			}
		}
	}

	return sc, err
}

func (p *Pool) processCommitments(c *scheduler.Committee, allowedStragglers uint16, timeout bool) (*SchedulerCommitment, error) { // nolint: gocyclo
	// Ensure we have at least scheduler's vote.
	sc, ok := p.SchedulerCommitments[p.HighestRank]
	switch {
	case !ok && timeout:
		// The round timer expired, but the schedulers haven't submitted any commitments.
		return nil, ErrNoSchedulerCommitment
	case !ok:
		// Wait for additional commitments or until the round timer expires.
		return nil, ErrStillWaiting

	}

	// Gather votes.
	var total, commits, failures int
	votes := make(map[hash.Hash]int)

	for _, n := range c.Members {
		switch {
		case !p.Discrepancy && n.Role != scheduler.RoleWorker:
			continue
		case p.Discrepancy && n.Role != scheduler.RoleBackupWorker:
			continue
		}

		total++
		vote, ok := sc.Votes[n.PublicKey]
		switch {
		case !ok:
			continue
		case vote == nil:
			failures++
		default:
			votes[*vote]++
		}
		commits++

		// Early discrepancy detection.
		switch {
		case p.Discrepancy:
			// Discrepancy resolution already started.
			continue
		case len(votes) <= 1 && failures <= int(allowedStragglers):
			// Discrepancy not detected.
			continue
		case p.HighestRank > 0 && !timeout:
			// To ensure fairness, the backup schedulers are always required to wait for a round
			// timeout. Without this delay, there is a risk that they could bypass the scheduling
			// order by convincing a few other nodes to instantly publish failures or discrepant
			// commitments.
			//
			// In the former scenario, the colliding nodes might avoid punishment because nodes
			// posting a failure are merely marked as 'not alive' for the current round, and no
			// slashing occurs. In the latter case, the colliding nodes may be penalized, but
			// the potential gains from being a scheduler could outweigh the losses.
			continue
		}

		// The committee is neither unanimous nor is the number of valid commitments expected to
		// surpass the required threshold due to numerous failures. Start discrepancy resolution.
		return nil, ErrDiscrepancyDetected
	}

	switch p.Discrepancy {
	case false:
		// Discrepancy detection.
		if len(votes) > 1 || failures > int(allowedStragglers) {
			// Early discrepancy detection will always identify discrepancies for the primary
			// scheduler. However, for the backup schedulers, this will only be the case
			// during timeouts. In other cases, the backup schedulers must await a round timeout.
			return nil, ErrStillWaiting
		}

		// Check if the majority has been reached.
		required := total - int(allowedStragglers)
		for _, v := range votes {
			// The map should have exactly one key/value pair, which indicates how many votes
			// the scheduler's commitment has received.
			required -= v
		}

		switch {
		case required > 0 && timeout:
			// The round timer expired, but the required number of votes hasn't been reached.
			return nil, ErrDiscrepancyDetected
		case required > 0:
			// Wait for additional commitments or until the round timer expires.
			return nil, ErrStillWaiting
		}
	case true:
		// Discrepancy resolution.
		required := total/2 + 1
		remaining := total - commits

		// Find the commit with the highest number of votes.
		var (
			hash hash.Hash
			best int
		)
		for h, v := range votes {
			if v > best {
				hash = h
				best = v
			}
		}

		switch {
		case best+remaining < required:
			// Fail the round if the majority cannot be reached due to insufficient votes remaining
			// (e.g. too many nodes have failed).
			return nil, ErrInsufficientVotes
		case best < required && timeout:
			// The round timer expired, but the majority hasn't been reached.
			return nil, ErrInsufficientVotes
		case best < required:
			// Wait for additional commitments or until the round timer expires.
			return nil, ErrStillWaiting
		case hash != sc.Commitment.ToVote():
			// The scheduler's commitment hasn't received the majority of the votes.
			return nil, ErrBadSchedulerCommitment
		}
	}

	return sc, nil
}
