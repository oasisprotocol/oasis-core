package commitment

import (
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestAdd(t *testing.T) {
	// Set chain domain separation context, required for signing commitments.
	genesisTestHelpers.SetTestChainContext()

	// Committee with 4 + 2 = 6 members,
	committee, err := generateCommittee(6, 4, 2)
	require.NoError(t, err)

	// Last block upon which commitments will be constructed.
	var id common.Namespace
	lastBlock := block.NewGenesisBlock(id, 0)

	// The next round is round 3, and the worker at position 1 will be the highest-ranked scheduler.
	// Formula: rank = (3 + position) % 4.
	lastBlock.Header.Round = 2

	// Empty pool.
	pool := NewPool()

	// Only members are allowed to submit commitments.
	outsider, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err)
	ec := generateMemberCommitment(committee, lastBlock, 0, 0)
	ec.NodeID = outsider.Public()
	err = ec.Sign(outsider, id)
	require.NoError(t, err)
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.Error(t, err, ErrNotInCommittee)

	// Only workers are allowed to schedule transactions.
	ec = generateMemberCommitment(committee, lastBlock, 3, 5) // Backup workers are not allowed.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	// Until the first scheduler commits, anyone can submit commitments.
	ec = generateMemberCommitment(committee, lastBlock, 3, 0) // Scheduler's rank is 3.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	ec = generateMemberCommitment(committee, lastBlock, 3, 1) // Scheduler's rank is 0.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	ec = generateMemberCommitment(committee, lastBlock, 3, 2) // Scheduler's rank is 1.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	ec = generateMemberCommitment(committee, lastBlock, 4, 0) // Scheduler's rank is 3.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	ec = generateMemberCommitment(committee, lastBlock, 4, 1) // Scheduler's rank is 0.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	// Duplicates are always forbidden.
	ec = generateMemberCommitment(committee, lastBlock, 3, 0) // Scheduler's rank is 3.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrAlreadyCommitted)

	// All commitments should be present in the pool.
	require.Equal(t, uint64(math.MaxUint64), pool.HighestRank)
	require.Len(t, pool.SchedulerCommitments, 3)

	require.Contains(t, pool.SchedulerCommitments, uint64(0))
	require.Contains(t, pool.SchedulerCommitments, uint64(1))
	require.Contains(t, pool.SchedulerCommitments, uint64(3))

	// A scheduler submits a commitment.
	ec = generateMemberCommitment(committee, lastBlock, 3, 3) // Scheduler's rank is 2.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	// Commitments with worse rank should be dropped.
	require.Equal(t, uint64(2), pool.HighestRank)
	require.Len(t, pool.SchedulerCommitments, 3)

	require.Contains(t, pool.SchedulerCommitments, uint64(0))
	require.Contains(t, pool.SchedulerCommitments, uint64(1))
	require.Contains(t, pool.SchedulerCommitments, uint64(2))

	// Commitments with worse rank should not be accepted.
	ec = generateMemberCommitment(committee, lastBlock, 5, 0) // Scheduler's rank is 3 (not ok).
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	ec = generateMemberCommitment(committee, lastBlock, 5, 3) // Scheduler's rank is 2.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	// A scheduler submits worse commitment.
	ec = generateMemberCommitment(committee, lastBlock, 0, 0) // Scheduler's rank is 3 (not ok).
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	// A scheduler submits better commitment.
	ec = generateMemberCommitment(committee, lastBlock, 2, 2) // Scheduler's rank is 1.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	// Commitments with worse rank should be dropped.
	require.Equal(t, uint64(1), pool.HighestRank)
	require.Len(t, pool.SchedulerCommitments, 2)

	require.Contains(t, pool.SchedulerCommitments, uint64(0))
	require.Contains(t, pool.SchedulerCommitments, uint64(1))

	// Commitments with worse priorities should not be accepted.
	ec = generateMemberCommitment(committee, lastBlock, 5, 3) // Scheduler's rank is 2 (not ok).
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	ec = generateMemberCommitment(committee, lastBlock, 5, 2) // Scheduler's rank is 1.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	// Enable discrepancy.
	pool.Discrepancy = true

	// All schedulers should be rejected.
	ec = generateMemberCommitment(committee, lastBlock, 3, 3) // Scheduler's rank is 2 (not ok).
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	ec = generateMemberCommitment(committee, lastBlock, 1, 1) // Scheduler's rank is 0 (not ok).
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	// All workers should be rejected.
	ec = generateMemberCommitment(committee, lastBlock, 0, 2) // Scheduler's rank is 1.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	ec = generateMemberCommitment(committee, lastBlock, 1, 2) // Scheduler's rank is 1.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)

	// Only commitments from backup workers with the same rank should be accepted.
	ec = generateMemberCommitment(committee, lastBlock, 4, 2) // Scheduler's rank is 1.
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.NoError(t, err)

	ec = generateMemberCommitment(committee, lastBlock, 4, 3) // Scheduler's rank is 2 (not ok).
	err = pool.AddVerifiedExecutorCommitment(committee, ec)
	require.ErrorIs(t, err, ErrBadExecutorCommitment)
}

func TestProcess(t *testing.T) {
	// Create a committee consisting of 8 members, with one member serving as both a worker (3)
	// and a backup worker (4).
	committee, err := generateCommittee(7, 4, 4)
	require.NoError(t, err)
	require.Len(t, committee.Members, 8)

	// Last block upon which commitments will be constructed.
	var id common.Namespace
	lastBlock := block.NewGenesisBlock(id, 0)

	// The next round is round 3, and the worker at position 1 will be the highest-ranked scheduler.
	// Formula: rank = (3 + position) % 4.
	lastBlock.Header.Round = 2

	var sc *SchedulerCommitment

	t.Run("Happy path, no discrepancy, no stragglers", func(t *testing.T) {
		pool := NewPool()
		allowedStragglers := uint16(0)

		// Add commitments from all workers.
		for i := 0; i < 4; i++ {
			// Not enough votes.
			sc, err = pool.ProcessCommitments(committee, allowedStragglers, false)
			require.ErrorIs(t, err, ErrStillWaiting)
			require.Nil(t, sc)

			// Add new commitment.
			ec := generateMemberCommitment(committee, lastBlock, i, 0)
			err = pool.AddVerifiedExecutorCommitment(committee, ec)
			require.NoError(t, err)
		}

		// Scheduler's commitment.
		ec := generateMemberCommitment(committee, lastBlock, 0, 0)

		// Enough votes (4/4).
		sc, err = pool.ProcessCommitments(committee, allowedStragglers, false)
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, ec, sc.Commitment)
		require.Len(t, sc.Votes, 4)
	})

	t.Run("Happy path, no discrepancy, allow stragglers", func(t *testing.T) {
		pool := NewPool()
		allowedStragglers := uint16(2)

		// Add commitments from few workers.
		for i := 0; i < 2; i++ {
			// Not enough votes.
			sc, err = pool.ProcessCommitments(committee, allowedStragglers, false)
			require.ErrorIs(t, err, ErrStillWaiting)
			require.Nil(t, sc)

			// Add new commitment.
			ec := generateMemberCommitment(committee, lastBlock, i, 0)
			err = pool.AddVerifiedExecutorCommitment(committee, ec)
			require.NoError(t, err)
		}

		// Scheduler's commitment.
		ec := generateMemberCommitment(committee, lastBlock, 0, 0)

		// Enough votes (2/4).
		sc, err = pool.ProcessCommitments(committee, allowedStragglers, false)
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, ec, sc.Commitment)
		require.Len(t, sc.Votes, 2)
	})

	t.Run("Happy path, discrepancy", func(t *testing.T) {
		pool := NewPool()

		// Add scheduler commitment.
		ec := generateMemberCommitment(committee, lastBlock, 0, 0)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Enable discrepancy resolution.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Add commitments from 3/4 backup workers.
		for i := 4; i < 7; i++ {
			// Not enough votes.
			sc, err = pool.ProcessCommitments(committee, 0, false)
			require.ErrorIs(t, err, ErrStillWaiting)
			require.Nil(t, sc)

			// Add new commitment.
			ec = generateMemberCommitment(committee, lastBlock, i, 0)
			err = pool.AddVerifiedExecutorCommitment(committee, ec)
			require.NoError(t, err)
		}

		// Scheduler's commitment.
		ec = generateMemberCommitment(committee, lastBlock, 0, 0)

		// Enough votes (3/4).
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, ec, sc.Commitment)
		require.Len(t, sc.Votes, 4)
	})

	t.Run("No scheduler commitments", func(t *testing.T) {
		pool := NewPool()

		// No commitments, no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// No commitments, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrNoSchedulerCommitment)
		require.Nil(t, sc)

		// Add commitments from all workers, except from the scheduler.
		for i := 1; i < 4; i++ {
			ec := generateMemberCommitment(committee, lastBlock, i, 0)
			err = pool.AddVerifiedExecutorCommitment(committee, ec)
			require.NoError(t, err)
		}

		// Commitments, no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Commitments, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrNoSchedulerCommitment)
		require.Nil(t, sc)

		// The rank should still be undefined.
		require.Equal(t, uint64(math.MaxUint64), pool.HighestRank)
	})

	t.Run("Discrepancy detection, not enough votes, primary scheduler", func(t *testing.T) {
		pool := NewPool()

		// One commit from worker, one from the scheduler.
		ec := generateMemberCommitment(committee, lastBlock, 2, 1)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		ec = generateMemberCommitment(committee, lastBlock, 1, 1)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Enough votes, no timeout
		sc, err = pool.ProcessCommitments(committee, 2, false)
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, ec, sc.Commitment)
		require.Len(t, sc.Votes, 2)

		// Enough votes, timeout.
		sc, err = pool.ProcessCommitments(committee, 2, false)
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, ec, sc.Commitment)
		require.Len(t, sc.Votes, 2)

		// Not enough votes, no timeout.
		sc, err = pool.ProcessCommitments(committee, 1, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Not enough votes, timeout.
		sc, err = pool.ProcessCommitments(committee, 1, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)
	})

	t.Run("Discrepancy detection, not enough votes, backup scheduler", func(t *testing.T) {
		pool := NewPool()

		// One commit from worker, one from the scheduler.
		ec := generateMemberCommitment(committee, lastBlock, 3, 2)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		ec = generateMemberCommitment(committee, lastBlock, 2, 2)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Enough votes, no timeout.
		sc, err = pool.ProcessCommitments(committee, 2, false)
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, ec, sc.Commitment)
		require.Len(t, sc.Votes, 2)

		// Enough votes, timeout.
		sc, err = pool.ProcessCommitments(committee, 2, false)
		require.NoError(t, err)
		require.NotNil(t, sc)
		require.Equal(t, ec, sc.Commitment)
		require.Len(t, sc.Votes, 2)

		// Not enough votes, no timeout.
		sc, err = pool.ProcessCommitments(committee, 1, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Not enough votes, timeout.
		sc, err = pool.ProcessCommitments(committee, 1, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)
	})

	t.Run("Discrepancy detection, unanimous votes, primary scheduler", func(t *testing.T) {
		pool := NewPool()

		// One commit from worker, one from the scheduler.
		ec := generateMemberCommitment(committee, lastBlock, 2, 1)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		ec = generateMemberCommitment(committee, lastBlock, 1, 1)
		ec.Header.Header.InMessagesCount = 10
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Unanimous votes, no timeout
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Unanimous votes, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)
	})

	t.Run("Discrepancy detection, unanimous votes, backup scheduler", func(t *testing.T) {
		pool := NewPool()

		// One commit from worker, one from the scheduler.
		ec := generateMemberCommitment(committee, lastBlock, 3, 2)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		ec = generateMemberCommitment(committee, lastBlock, 2, 2)
		ec.Header.Header.InMessagesCount = 10
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Unanimous votes, no timeout
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting) // Backup schedulers need to wait for timeout.
		require.Nil(t, sc)

		// Unanimous votes, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)
	})

	t.Run("Discrepancy detection, too many failures, primary scheduler", func(t *testing.T) {
		pool := NewPool()

		// One failure from the scheduler.
		ec := generateMemberFailure(committee, lastBlock, 1, 1)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Allow 1 failure, no timeout.
		sc, err = pool.ProcessCommitments(committee, 1, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Allow 1 failure, timeout.
		sc, err = pool.ProcessCommitments(committee, 1, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Allow 0 failures, no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Allow 0 failures, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Another failure.
		ec = generateMemberFailure(committee, lastBlock, 2, 1)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Allow 2 failures, no timeout.
		sc, err = pool.ProcessCommitments(committee, 2, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Allow 2 failures, timeout.
		sc, err = pool.ProcessCommitments(committee, 2, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Allow 1 failure, no timeout.
		sc, err = pool.ProcessCommitments(committee, 1, false)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Allow 1 failure, timeout.
		sc, err = pool.ProcessCommitments(committee, 1, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)
	})

	t.Run("Discrepancy detection, too many failures, backup scheduler", func(t *testing.T) {
		pool := NewPool()

		// One failure from the scheduler.
		ec := generateMemberFailure(committee, lastBlock, 2, 2)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Allow 1 failure, no timeout.
		sc, err = pool.ProcessCommitments(committee, 1, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Allow 1 failure, timeout.
		sc, err = pool.ProcessCommitments(committee, 1, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Allow 0 failures, no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting) // Backup schedulers need to wait for timeout.
		require.Nil(t, sc)

		// Allow 0 failures, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Another failure.
		ec = generateMemberFailure(committee, lastBlock, 3, 2)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Allow 2 failures, no timeout.
		sc, err = pool.ProcessCommitments(committee, 2, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Allow 2 failures, timeout.
		sc, err = pool.ProcessCommitments(committee, 2, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Restore pool.
		pool.Discrepancy = false

		// Allow 1 failure, no timeout.
		sc, err = pool.ProcessCommitments(committee, 1, false)
		require.ErrorIs(t, err, ErrStillWaiting) // Backup schedulers need to wait for timeout.
		require.Nil(t, sc)

		// Allow 1 failure, timeout.
		sc, err = pool.ProcessCommitments(committee, 1, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)
	})

	t.Run("Discrepancy resolution, not enough votes", func(t *testing.T) {
		pool := NewPool()

		// One commit from the scheduler.
		ec := generateMemberCommitment(committee, lastBlock, 0, 0)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Enable discrepancy resolution.
		sc, err = pool.ProcessCommitments(committee, 2, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// Not enough votes, no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Not enough votes, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrInsufficientVotes)
		require.Nil(t, sc)

		// Not enough votes (1/4, 3 left), no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Not enough votes (1/4, 3 left), timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrInsufficientVotes)
		require.Nil(t, sc)

		// Verify that one worker has two roles.
		ec = generateMemberCommitment(committee, lastBlock, 3, 0)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		ec = generateMemberCommitment(committee, lastBlock, 4, 0)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.ErrorIs(t, err, ErrAlreadyCommitted)

		// Another commit from a backup worker.
		ec = generateMemberCommitment(committee, lastBlock, 5, 0)
		ec.Header.Failure = FailureUnknown
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Not enough votes (1/4. 1/4, 2 left), no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Not enough votes (1/4. 1/4, 2 left), timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrInsufficientVotes)
		require.Nil(t, sc)

		// Another commit from a backup worker.
		ec = generateMemberCommitment(committee, lastBlock, 6, 0)
		ec.Header.Header.InMessagesCount = 10
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Not enough votes (1/4. 1/4. 1/4, 1 left), no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrInsufficientVotes) // Insufficient votes remaining.
		require.Nil(t, sc)

		// Not enough votes (1/4. 1/4. 1/4, 1 left), no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrInsufficientVotes)
		require.Nil(t, sc)

		// Revert last vote (hackish).
		delete(pool.SchedulerCommitments[3].Votes, ec.NodeID)

		// Another commit from a backup worker.
		ec = generateMemberCommitment(committee, lastBlock, 6, 0)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Not enough votes (2/4. 1/4, 1 left), no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrStillWaiting)
		require.Nil(t, sc)

		// Not enough votes (2/4. 1/4, 1 left), timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrInsufficientVotes)
		require.Nil(t, sc)

		// Another commit from a backup worker.
		ec = generateMemberCommitment(committee, lastBlock, 7, 0)
		ec.Header.Header.InMessagesCount = 10
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Not enough votes (2/4. 1/4, 1/4, 0 left), no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrInsufficientVotes)
		require.Nil(t, sc)

		// Not enough votes (2/4. 1/4, 1/4, 0 left), timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrInsufficientVotes)
		require.Nil(t, sc)
	})

	t.Run("Discrepancy resolution, bad scheduler commitment", func(t *testing.T) {
		pool := NewPool()

		// One commit from the scheduler.
		ec := generateMemberCommitment(committee, lastBlock, 0, 0)
		err = pool.AddVerifiedExecutorCommitment(committee, ec)
		require.NoError(t, err)

		// Enable discrepancy resolution.
		sc, err = pool.ProcessCommitments(committee, 2, true)
		require.ErrorIs(t, err, ErrDiscrepancyDetected)
		require.Nil(t, sc)

		// The majority of backup workers (3/4) disagrees with the scheduler.
		for i := 4; i < 7; i++ {
			ec := generateMemberCommitment(committee, lastBlock, i, 0)
			ec.Header.Header.InMessagesCount = 10
			err = pool.AddVerifiedExecutorCommitment(committee, ec)
			require.NoError(t, err)
		}

		// Bad scheduler commitment, no timeout.
		sc, err = pool.ProcessCommitments(committee, 0, false)
		require.ErrorIs(t, err, ErrBadSchedulerCommitment)
		require.Nil(t, sc)

		// Bad scheduler commitment, timeout.
		sc, err = pool.ProcessCommitments(committee, 0, true)
		require.ErrorIs(t, err, ErrBadSchedulerCommitment)
		require.Nil(t, sc)
	})
}

func TestVerify(t *testing.T) {
	ctx := context.Background()

	// Set chain domain separation context, required for signing commitments.
	genesisTestHelpers.SetTestChainContext()

	// Prepare a non-TEE runtime.
	var id common.Namespace
	err := id.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
	require.NoError(t, err)

	rtTEE := &registry.Runtime{
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          id,
		Kind:        registry.KindCompute,
		TEEHardware: node.TEEHardwareInvalid,
		Executor: registry.ExecutorParameters{
			MaxMessages: 32,
		},
		GovernanceModel: registry.GovernanceEntity,
	}

	// Generate node signing keys.
	worker, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err)
	backup, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err)

	// Prepare a simple committee.
	committee := &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: worker.Public(),
			},
			{
				Role:      scheduler.RoleBackupWorker,
				PublicKey: backup.Public(),
			},
		},
	}

	// Last block upon which commitments will be constructed.
	lastBlock := block.NewGenesisBlock(id, 0)

	t.Run("Verify", func(t *testing.T) {
		ec := generateCommitment(worker.Public(), worker.Public(), lastBlock, nil, nil)

		// Verify a valid signature.
		err = ec.Sign(worker, id)
		require.NoError(t, err)

		err = ec.Verify(id)
		require.NoError(t, err)

		// Verify invalid signature.
		ec.Signature[0]++ // Corrupt.

		err = ec.Verify(id)
		require.Error(t, err)
	})

	t.Run("Validate basic", func(t *testing.T) {
		// Valid commitment.
		ec := generateCommitment(worker.Public(), worker.Public(), lastBlock, nil, nil)

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		err = ec.ValidateBasic()
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
		require.NoError(t, err)

		// Invalid commitments.
		for _, tc := range []struct {
			name        string
			fn          func(*ExecutorCommitment)
			expectedErr error
		}{
			{"MissingIORootHash", func(ec *ExecutorCommitment) { ec.Header.Header.IORoot = nil }, ErrBadExecutorCommitment},
			{"MissingStateRootHash", func(ec *ExecutorCommitment) { ec.Header.Header.StateRoot = nil }, ErrBadExecutorCommitment},
			{"MissingMessagesHash", func(ec *ExecutorCommitment) { ec.Header.Header.MessagesHash = nil }, ErrBadExecutorCommitment},
			{"MissingInMessagesHash", func(ec *ExecutorCommitment) { ec.Header.Header.InMessagesHash = nil }, ErrBadExecutorCommitment},
			{"BadFailureIndicating", func(ec *ExecutorCommitment) { ec.Header.Failure = FailureUnknown }, ErrBadExecutorCommitment},
		} {
			ec := generateCommitment(worker.Public(), worker.Public(), lastBlock, nil, nil)

			tc.fn(ec)

			err = ec.Sign(worker, id)
			require.NoError(t, err)

			err = ec.ValidateBasic()
			require.Error(t, err)

			err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
			require.ErrorIs(t, err, tc.expectedErr)
		}
	})

	t.Run("Block chaining", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			fn          func(*ExecutorCommitment)
			expectedErr error
		}{
			{"BlockBadRound", func(ec *ExecutorCommitment) { ec.Header.Header.Round-- }, ErrNotBasedOnCorrectBlock},
			{"BlockBadPreviousHash", func(ec *ExecutorCommitment) { ec.Header.Header.PreviousHash.FromBytes([]byte("invalid")) }, ErrNotBasedOnCorrectBlock},
		} {
			ec := generateCommitment(worker.Public(), worker.Public(), lastBlock, nil, nil)

			tc.fn(ec)

			err = ec.Sign(worker, id)
			require.NoError(t, err)

			err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
			require.ErrorIs(t, err, tc.expectedErr)
		}
	})

	t.Run("Submitting failure", func(t *testing.T) {
		// Schedulers are not allowed to submit failures.
		ec := generateFailure(worker.Public(), worker.Public(), lastBlock)
		ec.Header.Failure = FailureUnknown

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
		require.ErrorIs(t, err, ErrBadExecutorCommitment)

		// Others are.
		ec = generateFailure(backup.Public(), worker.Public(), lastBlock)

		err = ec.Sign(backup, id)
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
		require.NoError(t, err)
	})

	t.Run("Emitted messages", func(t *testing.T) {
		// Prepare messages.
		msg := message.Message{
			Staking: &message.StakingMessage{
				Transfer: &staking.Transfer{},
			},
		}
		msgs := make([]message.Message, 0, rtTEE.Executor.MaxMessages)
		for i := 0; i < int(rtTEE.Executor.MaxMessages); i++ {
			msgs = append(msgs, msg)
		}

		// Non-schedulers are not allowed to emit messages.
		ec := generateCommitment(backup.Public(), worker.Public(), lastBlock, msgs, nil)

		err = ec.Sign(backup, id)
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
		require.ErrorIs(t, err, ErrInvalidMessages)

		// Only schedulers are.
		ec = generateCommitment(worker.Public(), worker.Public(), lastBlock, msgs, nil)

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
		require.NoError(t, err)

		// But not to many.
		tooManyMsgs := append(msgs, msg) // This should allocate a new array with larger capacity.

		ec = generateCommitment(worker.Public(), worker.Public(), lastBlock, tooManyMsgs, nil)

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
		require.ErrorIs(t, err, ErrInvalidMessages)

		// And the hash should match.
		ec = generateCommitment(worker.Public(), worker.Public(), lastBlock, msgs, nil)
		ec.Header.Header.MessagesHash[0]++ // Corrupt.

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nil)
		require.ErrorIs(t, err, ErrInvalidMessages)

		// And the messages should be valid.
		ec = generateCommitment(worker.Public(), worker.Public(), lastBlock, msgs, nil)

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		invalidMsgErr := fmt.Errorf("all messages are invalid")
		alwaysInvalidValidator := func(msgs []message.Message) error {
			return invalidMsgErr
		}

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, alwaysInvalidValidator, nil)
		require.ErrorIs(t, err, invalidMsgErr)

		// And they are.
		alwaysValidValidator := func(msgs []message.Message) error {
			return nil
		}

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, alwaysValidValidator, nil)
		require.NoError(t, err)
	})

	t.Run("TEE", func(t *testing.T) {
		// Prepare a TEE runtime.
		rtTEE = &registry.Runtime{
			Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
			ID:              id,
			Kind:            registry.KindCompute,
			TEEHardware:     node.TEEHardwareIntelSGX,
			GovernanceModel: registry.GovernanceEntity,
		}

		// Generate a dummy RAK.
		rak, err := memorySigner.NewSigner(rand.Reader)
		require.NoError(t, err)

		// Prepare commitment.
		ec := generateCommitment(worker.Public(), worker.Public(), lastBlock, nil, nil)

		rakSig, err := signature.Sign(rak, ComputeResultsHeaderSignatureContext, cbor.Marshal(ec.Header.Header))
		require.NoError(t, err)
		ec.Header.RAKSignature = &rakSig.Signature

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		// No runtime.
		nl := &staticNodeLookup{}

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nl)
		require.ErrorIs(t, err, ErrNoRuntime)

		// No node runtime.
		rtTEE.Deployments = []*registry.VersionInfo{
			{},
		}

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nl)
		require.ErrorIs(t, err, ErrNotInCommittee)

		// No TEE capabilities.
		nl = &staticNodeLookup{
			runtimes: []*node.Runtime{
				{
					ID: id,
				},
			},
		}

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nl)
		require.ErrorIs(t, err, ErrRakSigInvalid)

		// Valid RAK signature.
		nl = &staticNodeLookup{
			runtimes: []*node.Runtime{
				{
					ID: id,
					Capabilities: node.Capabilities{
						TEE: &node.CapabilityTEE{
							Hardware:    node.TEEHardwareIntelSGX,
							RAK:         rak.Public(),
							Attestation: []byte("My RAK is my attestation. Verify me."),
						},
					},
				},
			},
		}

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nl)
		require.NoError(t, err)

		// Invalid RAK signature.
		ec.Header.RAKSignature[0]++ // Corrupt.

		err = ec.Sign(worker, id)
		require.NoError(t, err)

		err = VerifyExecutorCommitment(ctx, lastBlock, rtTEE, committee.ValidFor, ec, nil, nl)
		require.ErrorIs(t, err, ErrRakSigInvalid)
	})
}

func generateCommittee(numNodes int, numWorkers int, numBackupWorkers int) (*scheduler.Committee, error) {
	if numWorkers > numNodes || numBackupWorkers > numNodes {
		return nil, fmt.Errorf("the number of workers or backup workers cannot exceed the total number of nodes")
	}

	// Prepare nodes.
	nodes := make([]signature.PublicKey, 0, numNodes)
	for i := 0; i < numNodes; i++ {
		signer, err := memorySigner.NewSigner(rand.Reader)
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, signer.Public())
	}

	// Generate a committee.
	committee := scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
	}

	for i := 0; i < numWorkers; i++ {
		committee.Members = append(committee.Members, &scheduler.CommitteeNode{
			Role:      scheduler.RoleWorker,
			PublicKey: nodes[i],
		})
	}

	for i := 0; i < numBackupWorkers; i++ {
		committee.Members = append(committee.Members, &scheduler.CommitteeNode{
			Role:      scheduler.RoleBackupWorker,
			PublicKey: nodes[len(nodes)-numBackupWorkers+i],
		})
	}

	return &committee, nil
}

func generateCommitment(nodeID signature.PublicKey, schedulerID signature.PublicKey, lastBlock *block.Block, msgs []message.Message, inMsgs []*message.IncomingMessage) *ExecutorCommitment {
	blk := block.NewEmptyBlock(lastBlock, 1, block.Normal)
	msgsHash := message.MessagesHash(msgs)
	inMsgsHash := message.InMessagesHash(inMsgs)

	return &ExecutorCommitment{
		NodeID: nodeID,
		Header: ExecutorCommitmentHeader{
			SchedulerID: schedulerID,
			Header: ComputeResultsHeader{
				Round:          blk.Header.Round,
				PreviousHash:   blk.Header.PreviousHash,
				IORoot:         &blk.Header.IORoot,
				StateRoot:      &blk.Header.StateRoot,
				MessagesHash:   &msgsHash,
				InMessagesHash: &inMsgsHash,
			},
		},
		Messages: msgs,
	}
}

func generateFailure(nodeID signature.PublicKey, schedulerID signature.PublicKey, lastBlock *block.Block) *ExecutorCommitment {
	blk := block.NewEmptyBlock(lastBlock, 1, block.Normal)

	return &ExecutorCommitment{
		NodeID: nodeID,
		Header: ExecutorCommitmentHeader{
			SchedulerID: schedulerID,
			Header: ComputeResultsHeader{
				Round:        blk.Header.Round,
				PreviousHash: blk.Header.PreviousHash,
			},
			Failure: FailureUnknown,
		},
	}
}

func generateMemberCommitment(committee *scheduler.Committee, lastBlock *block.Block, node int, scheduler int) *ExecutorCommitment {
	nodeID := committee.Members[node].PublicKey
	schedulerID := committee.Members[scheduler].PublicKey

	return generateCommitment(nodeID, schedulerID, lastBlock, nil, nil)
}

func generateMemberFailure(committee *scheduler.Committee, lastBlock *block.Block, node int, scheduler int) *ExecutorCommitment {
	nodeID := committee.Members[node].PublicKey
	schedulerID := committee.Members[scheduler].PublicKey

	return generateFailure(nodeID, schedulerID, lastBlock)
}

type staticNodeLookup struct {
	runtimes []*node.Runtime
}

func (n *staticNodeLookup) Node(_ context.Context, id signature.PublicKey) (*node.Node, error) {
	return &node.Node{
		Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:        id,
		Runtimes:  n.runtimes,
	}, nil
}
