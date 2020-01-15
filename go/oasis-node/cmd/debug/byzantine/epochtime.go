package byzantine

import (
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

func epochtimeWaitForEpoch(svc service.TendermintService, epoch epochtime.EpochTime) error {
	ch, sub := svc.EpochTime().WatchEpochs()
	defer sub.Close()

	for {
		currentEpoch := <-ch
		if currentEpoch >= epoch {
			return nil
		}
	}
}
