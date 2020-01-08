package byzantine

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/beacon"
	schedulerapp "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/scheduler"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
)

func hasSuitablePermutations(t *testing.T, beacon []byte, runtimeID common.Namespace) bool {
	numComputeNodes := 4
	computeIdxs, err := schedulerapp.GetPerm(beacon, runtimeID, schedulerapp.RNGContextCompute, numComputeNodes)
	require.NoError(t, err, "schedulerapp.GetPerm compute")
	transactionSchedulerIdxs, err := schedulerapp.GetPerm(beacon, runtimeID, schedulerapp.RNGContextTransactionScheduler, numComputeNodes)
	require.NoError(t, err, "schedulerapp.GetPerm transaction scheduler")
	mergeIdxs, err := schedulerapp.GetPerm(beacon, runtimeID, schedulerapp.RNGContextMerge, numComputeNodes)
	require.NoError(t, err, "schedulerapp.GetPerm merge")

	fmt.Printf("%20s schedule %v\n", scheduler.KindCompute, computeIdxs)
	fmt.Printf("%20s schedule %v\n", scheduler.KindTransactionScheduler, transactionSchedulerIdxs)
	fmt.Printf("%20s schedule %v\n", scheduler.KindMerge, mergeIdxs)

	committees := map[scheduler.CommitteeKind]struct {
		workers       int
		backupWorkers int
		perm          []int
	}{
		scheduler.KindCompute:              {workers: 2, backupWorkers: 1, perm: computeIdxs},
		scheduler.KindTransactionScheduler: {workers: 1, backupWorkers: 0, perm: transactionSchedulerIdxs},
		scheduler.KindMerge:                {workers: 2, backupWorkers: 1, perm: mergeIdxs},
	}

	for _, c1Kind := range []scheduler.CommitteeKind{
		scheduler.KindCompute,
		scheduler.KindMerge,
	} {
		c1 := committees[c1Kind]
		maxWorker := c1.workers
		foundSuitable := false
		for c1Pos := 0; c1Pos < maxWorker; c1Pos++ {
			c1Slot := c1.perm[c1Pos]
			conflict := false
		CheckConflicts:
			for c2Kind, c2 := range committees {
				if c2Kind == c1Kind {
					continue
				}
				totalScheduled := c2.workers + c2.backupWorkers
				for c2Pos := 0; c2Pos < totalScheduled; c2Pos++ {
					c2Slot := c2.perm[c2Pos]
					if c1Slot == c2Slot {
						conflict = true
						break CheckConflicts
					}
				}
			}
			if !conflict {
				fmt.Printf("suitable %s slot %d\n", c1Kind, c1Slot)
				foundSuitable = true
				break
			}
		}
		if !foundSuitable {
			fmt.Printf("no suitable %s slot\n", c1Kind)
			return false
		}
	}
	return true
}

func TestDebugSchedule(t *testing.T) {
	var epoch epochtime.EpochTime = 2
	var runtimeID common.Namespace
	require.NoError(t, runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000"), "runtimeID.UnmarshalHex")
	deterministicBeaconEntropy := []byte("If you change this, you will fuck up the byzantine tests!!")
	for {
		fmt.Printf("assessing seed %s\n", deterministicBeaconEntropy)

		b := beacon.GetBeacon(epoch, beacon.DebugEntropyCtx, deterministicBeaconEntropy)
		fmt.Printf("beacon %s\n", base64.StdEncoding.EncodeToString(b))

		if hasSuitablePermutations(t, b, runtimeID) {
			break
		}

		deterministicBeaconEntropy = append(deterministicBeaconEntropy, '!')
	}
}
