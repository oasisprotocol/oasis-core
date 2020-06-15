package committee

import (
	"context"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

type faultSubmitter interface {
	// SubmitExecutorCommit submits an executor commitment when a fault is detected.
	SubmitExecutorCommit(ctx context.Context, commit *commitment.ExecutorCommitment) error
}

type nodeFaultSubmitter struct {
	node *Node
}

// Implements faultSubmitter.
func (nf *nodeFaultSubmitter) SubmitExecutorCommit(ctx context.Context, commit *commitment.ExecutorCommitment) error {
	tx := roothash.NewExecutorCommitTx(0, nil, nf.node.commonNode.Runtime.ID(), []commitment.ExecutorCommitment{*commit})
	return consensus.SignAndSubmitTx(ctx, nf.node.commonNode.Consensus, nf.node.commonNode.Identity.NodeSigner, tx)
}

func newNodeFaultSubmitter(node *Node) faultSubmitter {
	return &nodeFaultSubmitter{node}
}

type faultDetector struct {
	runtime   runtimeRegistry.Runtime
	submitter faultSubmitter
	commit    *commitment.ExecutorCommitment

	quitCh  chan struct{}
	eventCh chan *roothash.Event

	logger *logging.Logger
}

func (d *faultDetector) notify(ev *roothash.Event) {
	select {
	case <-d.quitCh:
		// In case the worker has quit, prevent blocking on the event channel.
	case d.eventCh <- ev:
	}
}

func (d *faultDetector) submit(ctx context.Context) {
	d.logger.Warn("independently submitting executor commit")

	err := d.submitter.SubmitExecutorCommit(ctx, d.commit)
	switch err {
	case nil:
		d.logger.Info("independently submitted executor commit")
	default:
		d.logger.Error("failed to submit executor commit independently",
			"err", err,
		)
	}
}

func (d *faultDetector) worker(ctx context.Context) {
	// We should submit the commitment immediately in case when:
	//
	// - We see a merge commit that does not have our commitment.
	// - We see an executor commit.
	// - RoundTimeout elapses without seeing our commitment.
	//
	defer close(d.quitCh)

	// Determine the round timeout and start a local timer.
	rtDesc, err := d.runtime.RegistryDescriptor(ctx)
	if err != nil {
		d.logger.Error("failed to retrieve runtime registry descriptor",
			"err", err,
		)
		return
	}
	// Add a small amount to compensate for network latency.
	timer := time.NewTimer(rtDesc.Executor.RoundTimeout + 1*time.Second)

	// Extract committee ID for easier comparison.
	openCommit, err := d.commit.Open()
	if err != nil {
		// This should NEVER happen.
		d.logger.Error("bad own commitment",
			"err", err,
		)
		return
	}

	// TODO: Once we have P2P gossipsub also look at gossiped commitments in addition to consensus.

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// Local round timeout expired.
			d.logger.Warn("local round timeout expired without seeing our commitment")
			go d.submit(ctx)
			return
		case ev := <-d.eventCh:
			// Received a roothash event for our runtime.
			switch {
			case ev.ExecutorCommitted != nil:
				// Executor committed independently, check if it is for our committee.
				ec, err := ev.ExecutorCommitted.Commit.Open()
				if err != nil {
					// This should NEVER happen as the consensus backend verifies this.
					d.logger.Error("bad executor commitment from consensus backend?",
						"err", err,
					)
					continue
				}

				if !ec.Body.CommitteeID.Equal(&openCommit.Body.CommitteeID) {
					continue
				}

				// If this is our own commit (in theory anyone could submit it on our behalf), we
				// don't need to do anything.
				if ec.Equal(d.commit) {
					d.logger.Info("our commitment has been submitted to consensus layer by an external party")
					return
				}

				// Executor committed independently, we should too as this means that so far we have
				// not seen any separate commitments.
				d.logger.Warn("seen another executor independently submit commitments, following",
					"executor_node_id", ev.ExecutorCommitted.Commit.Signature.PublicKey,
				)
				go d.submit(ctx)
				return
			case ev.MergeCommitted != nil:
				// Merge node committed. If our commit is included, then we can stop as there is at
				// least one honest merge node.
				mc, err := ev.MergeCommitted.Commit.Open()
				if err != nil {
					// This should NEVER happen as the consensus backend verifies this.
					d.logger.Error("bad merge commitment from consensus backend?",
						"err", err,
					)
					continue
				}

				for _, ec := range mc.Body.ExecutorCommits {
					if ec.Equal(d.commit) {
						// Found our commitment, stop right here.
						d.logger.Info("our commitment has been submitted to consensus layer by an honest merge node")
						return
					}
				}

				// A merge node submitted commitments but didn't include ours.
				d.logger.Warn("seen merge commitment without our commitment",
					"merge_node_id", ev.MergeCommitted.Commit.Signature.PublicKey,
				)
				go d.submit(ctx)
				return
			}
		}
	}
}

func newFaultDetector(
	ctx context.Context,
	rt runtimeRegistry.Runtime,
	commit *commitment.ExecutorCommitment,
	submitter faultSubmitter,
) *faultDetector {
	d := &faultDetector{
		runtime:   rt,
		submitter: submitter,
		commit:    commit,
		quitCh:    make(chan struct{}),
		eventCh:   make(chan *roothash.Event),
		logger:    logging.GetLogger("worker/executor/committee/fault").With("runtime_id", rt.ID()),
	}
	go d.worker(ctx)
	return d
}
