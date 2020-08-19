package byzantine

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	beaconapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/beacon"
	schedulerapp "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

func hasSuitablePermutations(t *testing.T, beacon []byte, runtimeID common.Namespace) bool {
	numComputeNodes := 4
	computeIdxs, err := schedulerapp.GetPerm(beacon, runtimeID, schedulerapp.RNGContextExecutor, numComputeNodes)
	require.NoError(t, err, "schedulerapp.GetPerm compute")

	t.Logf("%20s schedule %v\n", scheduler.KindComputeExecutor, computeIdxs)

	committees := map[scheduler.CommitteeKind]struct {
		workers       int
		backupWorkers int
		perm          []int
	}{
		scheduler.KindComputeExecutor: {workers: 2, backupWorkers: 1, perm: computeIdxs},
	}

	for _, c1Kind := range []scheduler.CommitteeKind{
		scheduler.KindComputeExecutor,
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
				t.Logf("suitable %s slot %d\n", c1Kind, c1Slot)
				foundSuitable = true
				break
			}
		}
		if !foundSuitable {
			t.Logf("no suitable %s slot\n", c1Kind)
			return false
		}
	}
	return true
}

func TestDebugSchedule(t *testing.T) {
	var epoch beacon.EpochTime = 2
	var runtimeID common.Namespace
	require.NoError(t, runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000"), "runtimeID.UnmarshalHex")
	deterministicBeaconEntropy := append([]byte{}, beaconapp.DebugEntropy...)
	for {
		t.Logf("assessing seed: '%s'\n", deterministicBeaconEntropy)

		b := beaconapp.GetBeacon(epoch, beaconapp.DebugEntropyCtx, deterministicBeaconEntropy)
		t.Logf("beacon: '%s'\n", base64.StdEncoding.EncodeToString(b))

		if hasSuitablePermutations(t, b, runtimeID) {
			break
		}

		deterministicBeaconEntropy = append(deterministicBeaconEntropy, '!')
	}
}
