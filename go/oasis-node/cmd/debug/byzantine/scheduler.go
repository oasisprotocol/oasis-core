package byzantine

import (
	"context"
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

func schedulerNextElectionHeight(svc consensus.Backend, epoch beacon.EpochTime) (int64, error) {
	ch, sub, err := svc.Scheduler().WatchCommittees(context.Background())
	if err != nil {
		return -1, fmt.Errorf("failed to watch committees: %w", err)
	}
	defer sub.Close()

	for {
		if committee := <-ch; committee.ValidFor >= epoch {
			height, err := svc.Beacon().GetEpochBlock(context.Background(), committee.ValidFor)
			if err != nil {
				return -1, fmt.Errorf("failed to get epoch block: %w", err)
			}
			return height, nil
		}
	}
}

func schedulerGetCommittee(ht *honestTendermint, height int64, kind scheduler.CommitteeKind, runtimeID common.Namespace) (*scheduler.Committee, error) {
	committees, err := ht.service.Scheduler().GetCommittees(context.Background(), &scheduler.GetCommitteesRequest{
		RuntimeID: runtimeID,
		Height:    height,
	})
	if err != nil {
		return nil, fmt.Errorf("Scheduler GetCommittees() error: %w", err)
	}

	for _, committee := range committees {
		if committee.Kind != kind {
			continue
		}

		if !committee.RuntimeID.Equal(&runtimeID) {
			continue
		}

		return committee, nil
	}
	return nil, fmt.Errorf("query didn't return a committee for our runtime")
}

func schedulerCheckScheduled(committee *scheduler.Committee, nodeID signature.PublicKey, role scheduler.Role) error {
	for _, member := range committee.Members {
		if !member.PublicKey.Equal(nodeID) {
			continue
		}

		if member.Role != role {
			return fmt.Errorf("we're scheduled as %s, expected %s", member.Role, role)
		}

		// All good.
		return nil
	}
	if role == scheduler.RoleInvalid {
		// It's expected that we're not scheduled.
		return nil
	}
	return fmt.Errorf("we're not scheduled")
}

func schedulerCheckTxScheduler(committee *scheduler.Committee, nodeID signature.PublicKey, round uint64) bool {
	scheduler, err := commitment.GetTransactionScheduler(committee, round)
	if err != nil {
		panic(err)
	}
	return scheduler.PublicKey.Equal(nodeID)
}

func schedulerForRoleInCommittee(ht *honestTendermint, height int64, committee *scheduler.Committee, role scheduler.Role, fn func(*node.Node) error) error {
	for _, member := range committee.Members {
		if member.Role != role {
			continue
		}

		n, err := registryGetNode(ht, height, member.PublicKey)
		if err != nil {
			return fmt.Errorf("registry get node %s error: %w", member.PublicKey, err)
		}

		if err = fn(n); err != nil {
			// Forward callback error to caller verbatim.
			return err
		}
	}

	return nil
}
