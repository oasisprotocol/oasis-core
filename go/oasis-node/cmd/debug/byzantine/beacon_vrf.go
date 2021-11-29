package byzantine

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// LogEventVRFBeaconRoundCompleted is the event emitted when the byzantine
// VRF beacon (in)correctly executes a round.
const LogEventVRFBeaconRoundCompleted = "byzantine/vrf_beacon/round_completed"

// VRFBeaconMode represents the byzantine VRF beacon mode.
type VRFBeaconMode uint32

// VRF Beacon modes.
const (
	ModeVRFBeaconHonest VRFBeaconMode = iota
	ModeVRFBeaconEarly
	ModeVRFBeaconMissing

	modeVRFBeaconHonestString  = "vrf_beacon_honest"
	modeVRFBeaconEarlyString   = "vrf_beacon_early"
	modeVRFBeaconMissingString = "vrf_beacon_missing"
)

// String returns a string representation of a VRF beacon mode.
func (m VRFBeaconMode) String() string {
	switch m {
	case ModeVRFBeaconHonest:
		return modeVRFBeaconHonestString
	case ModeVRFBeaconEarly:
		return modeVRFBeaconEarlyString
	case ModeVRFBeaconMissing:
		return modeVRFBeaconMissingString
	default:
		return "[unsupported VRF beacon mode]"
	}
}

// FromString deserializes a string into a beacon mode.
func (m *VRFBeaconMode) FromString(s string) error {
	switch strings.ToLower(s) {
	case modeVRFBeaconHonestString:
		*m = ModeVRFBeaconHonest
	case modeVRFBeaconEarlyString:
		*m = ModeVRFBeaconEarly
	case modeVRFBeaconMissingString:
		*m = ModeVRFBeaconMissing
	default:
		return fmt.Errorf("invalid VRF beacon mode kind: '%s'", m)
	}

	return nil
}

func doVRFBeaconScenario(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	var runtimeID common.Namespace
	if err := runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID)); err != nil {
		panic(fmt.Errorf("error initializing node: failed to parse runtime ID: %w", err))
	}

	var mode VRFBeaconMode
	if err := mode.FromString(viper.GetString(CfgVRFBeaconMode)); err != nil {
		panic(err)
	}

	b, err := initializeAndRegisterByzantineNode(runtimeID, node.RoleValidator, scheduler.RoleInvalid, false, true)
	if err != nil {
		panic(fmt.Sprintf("error initializing node: %+v", err))
	}
	defer func() {
		_ = b.stop()
	}()

	baseBackend := b.tendermint.service.Beacon()
	backend, ok := baseBackend.(beacon.VRFBackend)
	if !ok {
		panic("beacon not configured for VRF backend")
	}

	// Start watching for VRF events
	ch, sub, err := backend.WatchLatestVRFEvent(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to subscribe to VRF events: %+v", err))
	}
	defer sub.Close()

	// Wait for the initial VRF event.
	logger.Info("waiting on initial VRF event")
	ev, ok := <-ch
	if !ok {
		panic("VRF event channel closed")
	}

	var iter int
	for {
		logger.Debug("executing beacon round",
			"iteration", iter,
		)

		if ev, err = doVRFBeaconRound(ctx, b, backend, ch, ev, mode); err != nil {
			panic(fmt.Sprintf("failed beacon round: %v", err))
		}

		logger.Info("executed beacon round",
			"iteration", iter,
			logging.LogEvent, LogEventVRFBeaconRoundCompleted,
		)

		iter++
	}
}

func doVRFBeaconRound(
	ctx context.Context,
	b *byzantine,
	backend beacon.VRFBackend,
	ch <-chan *beacon.VRFEvent,
	ev *beacon.VRFEvent,
	mode VRFBeaconMode,
) (*beacon.VRFEvent, error) {
	logger.Info("received VRF beacon event",
		"epoch", ev.Epoch,
		"alpha", hex.EncodeToString(ev.Alpha),
		"submit_after", ev.SubmitAfter,
	)

	if mode == ModeVRFBeaconMissing {
		logger.Info("mode is 'missing', skipping proof submission")
	} else {
		if mode == ModeVRFBeaconHonest {
			height, err := waitTillHeightAtLeast(ctx, b, ev.SubmitAfter)
			if err != nil {
				return nil, fmt.Errorf("failed to wait for height: %w", err)
			}

			logger.Info("height is at least ev.SubmitAfter",
				"height", height,
				"submit_after", ev.SubmitAfter,
			)
		} else {
			logger.Info("mode is 'early', ignoring ev.SubmitAfter")
		}

		// Submit the proof.
		pi, err := signature.Prove(b.identity.VRFSigner, ev.Alpha)
		if err != nil {
			return nil, fmt.Errorf("failed to generate VRF proof: %w", err)
		}
		proofPayload := beacon.VRFProve{
			Epoch: ev.Epoch,
			Pi:    pi.Proof[:],
		}
		tx := transaction.NewTransaction(0, nil, beacon.MethodVRFProve, proofPayload)
		err = consensus.SignAndSubmitTx(ctx, b.tendermint.service, b.identity.NodeSigner, tx)
		switch mode {
		case ModeVRFBeaconHonest:
			if err != nil {
				return nil, fmt.Errorf("failed to submit proof tx: %w", err)
			}
			logger.Info("submitted proof")
		default:
			if err == nil {
				return nil, fmt.Errorf("succeeded in submitting proof with no wait")
			}
			logger.Info("failed to submit proof",
				"err", err,
			)
		}
	}

	logger.Info("waiting till epoch transition")

	newEv := <-ch
	transitionHeight, err := backend.GetEpochBlock(ctx, newEv.Epoch)
	if err != nil {
		return nil, fmt.Errorf("failed to get epoch transition height: %w", err)
	}

	logger.Info("received new VRF beacon event",
		"epoch", newEv.Epoch,
		"transition_height", transitionHeight,
	)

	// The best we can do for now is to check that our proof was recorded
	// if it was supposed to be, because validators that do not submit
	// proofs are still eligible to be validators.
	//
	// This could try and elect a committee or something, but getting the
	// byzantine node to go through the required motions for that is
	// going to be nightmarish.
	//
	// This is probably good enough for now, testing can actually happen
	// once validators are required to submit proofs.

	if newEv.Epoch <= ev.Epoch {
		return nil, fmt.Errorf("epoch did not advance")
	}

	prevHeight := transitionHeight - 1
	vrfState, err := backend.GetVRFState(ctx, prevHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to query VRF state for height '%d': %w", prevHeight, err)
	}

	logger.Info("got previous state",
		"prev_epoc", vrfState.Epoch,
	)

	if vrfState.Epoch != ev.Epoch {
		return nil, fmt.Errorf("got VRF state for unexpected epoch")
	}

	switch mode {
	case ModeVRFBeaconHonest:
		if vrfState.Pi[b.identity.NodeSigner.Public()] == nil {
			return nil, fmt.Errorf("proof missing in VRF state")
		}
	default:
		if vrfState.Pi[b.identity.NodeSigner.Public()] != nil {
			return nil, fmt.Errorf("proof present in VRF state")
		}
	}

	return newEv, nil
}

func waitTillHeightAtLeast(
	ctx context.Context,
	b *byzantine,
	height int64,
) (int64, error) {
	ch, sub, err := b.tendermint.service.WatchBlocks(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to watch blocks: %w", err)
	}
	defer sub.Close()

	for {
		blk := <-ch
		if blk.Height >= height {
			return blk.Height, nil
		}
	}
}
