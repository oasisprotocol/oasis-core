package committee

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	"github.com/oasisprotocol/oasis-core/go/runtime/localstorage"
	"github.com/oasisprotocol/oasis-core/go/runtime/tagindexer"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

type testFaultSubmitter struct {
	sync.Mutex

	faults []commitment.ExecutorCommitment
}

// Implements faultSubmitter.
func (tf *testFaultSubmitter) SubmitExecutorCommit(ctx context.Context, commit *commitment.ExecutorCommitment) error {
	tf.Lock()
	defer tf.Unlock()

	tf.faults = append(tf.faults, *commit)
	return nil
}

func (tf *testFaultSubmitter) getFaults() []commitment.ExecutorCommitment {
	tf.Lock()
	defer tf.Unlock()

	return append([]commitment.ExecutorCommitment{}, tf.faults...)
}

type testRuntime struct {
}

// Implements runtimeRegistry.Runtime.
func (rt *testRuntime) ID() common.Namespace {
	return common.Namespace{}
}

// Implements runtimeRegistry.Runtime.
func (rt *testRuntime) RegistryDescriptor(ctx context.Context) (*registry.Runtime, error) {
	return &registry.Runtime{}, nil
}

// Implements runtimeRegistry.Runtime.
func (rt *testRuntime) WatchRegistryDescriptor() (<-chan *registry.Runtime, pubsub.ClosableSubscription, error) {
	panic("not implemented")
}

// Implements runtimeRegistry.Runtime.
func (rt *testRuntime) History() history.History {
	panic("not implemented")
}

// Implements runtimeRegistry.Runtime.
func (rt *testRuntime) TagIndexer() tagindexer.QueryableBackend {
	panic("not implemented")
}

// Implements runtimeRegistry.Runtime.
func (rt *testRuntime) Storage() storage.Backend {
	panic("not implemented")
}

// Implements runtimeRegistry.Runtime.
func (rt *testRuntime) LocalStorage() localstorage.LocalStorage {
	panic("not implemented")
}

func TestFaultDetector(t *testing.T) {
	require := require.New(t)

	genesisTestHelpers.SetTestChainContext()

	signer := memorySigner.NewTestSigner("worker/compute/executor/committee/fault test")
	commit, err := commitment.SignExecutorCommitment(signer, &commitment.ComputeBody{})
	require.NoError(err, "SignExecutorCommitment")

	rt := testRuntime{}

	for _, tc := range []struct {
		name string
		fn   func(*testing.T, *faultDetector, *testFaultSubmitter, *commitment.ExecutorCommitment)
	}{
		{"Timeout", testFaultDetectorTimeout},
		{"EarlyExecutor", testFaultDetectorEarlyExecutor},
		{"ExternalSubmission", testFaultDetectorExternalSubmission},
		{"FaultyMerge", testFaultDetectorFaultyMerge},
		{"HonestMerge", testFaultDetectorHonestMerge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tf := testFaultSubmitter{}
			fd := newFaultDetector(ctx, &rt, commit, &tf)

			tc.fn(t, fd, &tf, commit)
		})
	}
}

func testFaultDetectorTimeout(t *testing.T, fd *faultDetector, tf *testFaultSubmitter, commit *commitment.ExecutorCommitment) {
	require := require.New(t)

	// The fault detector should timeout in one second even if we don't do any notifies.
	time.Sleep(1200 * time.Millisecond)

	faults := tf.getFaults()
	require.Len(faults, 1, "fault detector should submit commitment after timeout")
	require.EqualValues(*commit, faults[0], "the submitted commitment should be the same")
}

func testFaultDetectorEarlyExecutor(t *testing.T, fd *faultDetector, tf *testFaultSubmitter, commit *commitment.ExecutorCommitment) {
	require := require.New(t)

	signer := memorySigner.NewTestSigner("worker/compute/executor/committee/fault test: EarlyExecutor")
	earlyCommit, err := commitment.SignExecutorCommitment(signer, &commitment.ComputeBody{
		CommitteeID: hash.NewFromBytes([]byte("EarlyExecutorBadCommitteeID")),
	})
	require.NoError(err, "SignExecutorCommitment")

	// Nothing should happen if the commitee ID doesn't match.
	fd.notify(&roothash.Event{
		ExecutorCommitted: &roothash.ExecutorCommittedEvent{
			Commit: *earlyCommit,
		},
	})
	// Give the fault detector some time to process requests.
	time.Sleep(100 * time.Millisecond)
	// There should be no submissions.
	faults := tf.getFaults()
	require.Len(faults, 0, "fault detector should not submit anything in case of events for other committees")

	// Notify the detector of an early executor submitting their commitment.
	earlyCommit, err = commitment.SignExecutorCommitment(signer, &commitment.ComputeBody{})
	require.NoError(err, "SignExecutorCommitment")

	fd.notify(&roothash.Event{
		ExecutorCommitted: &roothash.ExecutorCommittedEvent{
			Commit: *earlyCommit,
		},
	})
	// Give the fault detector some time to process requests.
	time.Sleep(100 * time.Millisecond)
	// There should be a submission.
	faults = tf.getFaults()
	require.Len(faults, 1, "fault detector should submit commitment after early executor")
	require.EqualValues(*commit, faults[0], "the submitted commitment should be the same")
}

func testFaultDetectorExternalSubmission(t *testing.T, fd *faultDetector, tf *testFaultSubmitter, commit *commitment.ExecutorCommitment) {
	require := require.New(t)

	// Notify the detector of an external process submitting our commitment.
	fd.notify(&roothash.Event{
		ExecutorCommitted: &roothash.ExecutorCommittedEvent{
			Commit: *commit,
		},
	})
	// Give the fault detector some time to process requests.
	time.Sleep(100 * time.Millisecond)
	// There should not be a submission.
	faults := tf.getFaults()
	require.Len(faults, 0, "fault detector should not submit commitment after seeing own commit")

	// The fault detector should stop after seeing an honest merge node, so even waiting for the
	// timeout amount should not trigger it.
	time.Sleep(1200 * time.Millisecond)

	faults = tf.getFaults()
	require.Len(faults, 0, "fault detector should be stopped")
}

func testFaultDetectorFaultyMerge(t *testing.T, fd *faultDetector, tf *testFaultSubmitter, commit *commitment.ExecutorCommitment) {
	require := require.New(t)

	signer := memorySigner.NewTestSigner("worker/compute/executor/committee/fault test: FaultyMerge")
	earlyCommit, err := commitment.SignExecutorCommitment(signer, &commitment.ComputeBody{})
	require.NoError(err, "SignExecutorCommitment")

	mergeCommit, err := commitment.SignMergeCommitment(signer, &commitment.MergeBody{
		ExecutorCommits: []commitment.ExecutorCommitment{*earlyCommit},
	})
	require.NoError(err, "SignMergeCommitment")

	// Notify the detector of a merge commit that does not include own commit.
	fd.notify(&roothash.Event{
		MergeCommitted: &roothash.MergeCommittedEvent{
			Commit: *mergeCommit,
		},
	})
	// Give the fault detector some time to process requests.
	time.Sleep(100 * time.Millisecond)
	// There should be a submission.
	faults := tf.getFaults()
	require.Len(faults, 1, "fault detector should submit commitment after merge without own commit")
	require.EqualValues(*commit, faults[0], "the submitted commitment should be the same")
}

func testFaultDetectorHonestMerge(t *testing.T, fd *faultDetector, tf *testFaultSubmitter, commit *commitment.ExecutorCommitment) {
	require := require.New(t)

	signer := memorySigner.NewTestSigner("worker/compute/executor/committee/fault test: HonestMerge")
	earlyCommit, err := commitment.SignExecutorCommitment(signer, &commitment.ComputeBody{})
	require.NoError(err, "SignExecutorCommitment")

	// Merge commit that includes our commit -- should not trigger a submission.
	mergeCommit, err := commitment.SignMergeCommitment(signer, &commitment.MergeBody{
		ExecutorCommits: []commitment.ExecutorCommitment{*commit, *earlyCommit},
	})
	require.NoError(err, "SignMergeCommitment")

	// Notify the detector of a merge commit that includes own commit.
	fd.notify(&roothash.Event{
		MergeCommitted: &roothash.MergeCommittedEvent{
			Commit: *mergeCommit,
		},
	})
	// Give the fault detector some time to process requests.
	time.Sleep(100 * time.Millisecond)
	// There should not be a submission.
	faults := tf.getFaults()
	require.Len(faults, 0, "fault detector should not submit commitment after merge without own commit")

	// The fault detector should stop after seeing an honest merge node, so even waiting for the
	// timeout amount should not trigger it.
	time.Sleep(1200 * time.Millisecond)

	faults = tf.getFaults()
	require.Len(faults, 0, "fault detector should be stopped")
}
