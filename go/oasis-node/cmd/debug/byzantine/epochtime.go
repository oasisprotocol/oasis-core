package byzantine

import (
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

func epochtimeWaitForEpoch(svc consensus.Backend, epoch epochtime.EpochTime) error {
	ch, sub := svc.EpochTime().WatchEpochs()
	defer sub.Close()

	for {
		currentEpoch := <-ch
		if currentEpoch >= epoch {
			return nil
		}
	}
}
