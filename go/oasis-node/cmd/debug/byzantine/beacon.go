package byzantine

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/pvss"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// LogEventBeaconRoundCompleted is the event emitted when the byzantine
// beacon (in)correctly executes a round.
const LogEventBeaconRoundCompleted = "byzantine/beacon/round_completed"

// BeaconMode represents the byzantine beacon mode.
type BeaconMode uint32

// BeaconModes.
const (
	ModeBeaconHonest BeaconMode = iota
	ModeBeaconCommitStraggler
	ModeBeaconRevealStraggler

	modeBeaconHonestString    = "beacon_honest"
	modeBeaconCommitStraggler = "commit_straggler"
	modeBeaconRevealStraggler = "reveal_straggler"
)

// String returns a string representation of a beacon mode.
func (m BeaconMode) String() string {
	switch m {
	case ModeBeaconHonest:
		return modeBeaconHonestString
	case ModeBeaconCommitStraggler:
		return modeBeaconCommitStraggler
	case ModeBeaconRevealStraggler:
		return modeBeaconRevealStraggler
	default:
		return "[unsupported beacon mode]"
	}
}

// FromString deserializes a string into a beacon mode.
func (m *BeaconMode) FromString(s string) error {
	switch strings.ToLower(s) {
	case modeBeaconHonestString:
		*m = ModeBeaconHonest
	case modeBeaconCommitStraggler:
		*m = ModeBeaconCommitStraggler
	case modeBeaconRevealStraggler:
		*m = ModeBeaconRevealStraggler
	default:
		return fmt.Errorf("invalid beacon mode kind: %s", m)
	}

	return nil
}

func doBeaconScenario(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	var runtimeID common.Namespace
	if err := runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID)); err != nil {
		panic(fmt.Errorf("error initializing node: failed to parse runtime ID: %w", err))
	}

	var mode BeaconMode
	if err := mode.FromString(viper.GetString(CfgBeaconMode)); err != nil {
		panic(err)
	}

	b, err := initializeAndRegisterByzantineNode(runtimeID, node.RoleValidator, scheduler.RoleInvalid, scheduler.RoleInvalid, false, true)
	if err != nil {
		panic(fmt.Sprintf("error initializing node: %+v", err))
	}
	defer func() {
		_ = b.stop()
	}()

	baseBackend := b.tendermint.service.Beacon()
	backend, ok := baseBackend.(beacon.PVSSBackend)
	if !ok {
		panic("beacon not configured for PVSS backend")
	}

	// Start watching for PVSS events
	ch, sub, err := backend.WatchLatestPVSSEvent(ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to subscribe to PVSS events: %+v", err))
	}
	defer sub.Close()

	var iter int
	for {
		logger.Debug("executing beacon round",
			"iteration", iter,
		)

		if err = doBeaconRound(ctx, b, backend, ch, mode); err != nil {
			panic(fmt.Sprintf("failed beacon round: %v", err))
		}

		logger.Info("executed beacon round",
			"iteration", iter,
			logging.LogEvent, LogEventBeaconRoundCompleted,
		)

		iter++
	}
}

func doBeaconRound(
	ctx context.Context,
	b *byzantine,
	backend beacon.PVSSBackend,
	ch <-chan *beacon.PVSSEvent,
	mode BeaconMode,
) error {
	var err error

	// Wait for the commit state, where we are a participant
	var state *beacon.PVSSState
commitWaitLoop:
	for {
		if state, err = waitForBeaconState(ctx, backend, ch, beacon.StateCommit, false); err != nil {
			return fmt.Errorf("failed to wait on StateCommit: %w", err)
		}

		// That we are a participant in...
		for _, v := range state.Participants {
			if v.Equal(b.identity.NodeSigner.Public()) {
				logger.Debug("StateCommit",
					"epoch", state.Epoch,
					"round", state.Round,
				)
				break commitWaitLoop
			}
		}

		logger.Debug("StateCommit, not a participant",
			"epoch", state.Epoch,
			"round", state.Round,
		)
	}

	// Initialize the local instance
	instance, err := pvss.New(&pvss.Config{
		PrivateKey:   &b.identity.BeaconScalar,
		Participants: state.Instance.Participants,
		Threshold:    state.Instance.Threshold,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize PVSS instance: %w", err)
	}

	// Commit
	var shouldBeBad bool
	switch mode {
	case ModeBeaconCommitStraggler:
		logger.Debug("skipping commit")
		shouldBeBad = true
	default:
		var commit *pvss.Commit
		if commit, err = instance.Commit(); err != nil {
			return fmt.Errorf("failed to generate commit: %w", err)
		}
		commitPayload := beacon.PVSSCommit{
			Epoch:  state.Epoch,
			Round:  state.Round,
			Commit: commit,
		}
		tx := transaction.NewTransaction(0, nil, beacon.MethodPVSSCommit, commitPayload)
		if err = consensus.SignAndSubmitTx(ctx, b.tendermint.service, b.identity.NodeSigner, tx); err != nil {
			return fmt.Errorf("failed to submit commit tx: %w", err)
		}
	}

	// Wait for the reveal state
	if state, err = waitForBeaconState(ctx, backend, ch, beacon.StateReveal, true); err != nil {
		return fmt.Errorf("failed to wait on StateReveal: %w", err)
	}
	if isBad := state.BadParticipants[b.identity.NodeSigner.Public()]; isBad != shouldBeBad {
		return fmt.Errorf("unexpected bad participant status after commit: %v", isBad)
	}

	// Reveal
	for i := 0; i < len(state.Participants); i++ {
		cs := state.Instance.Commits[i]
		if cs == nil || instance.Commits[i] != nil {
			continue
		}
		if err = instance.OnCommit(cs.Commit); err != nil {
			return fmt.Errorf("state contains invalid commit: %w", err)
		}
	}
	if ok, totalCommits := instance.MayReveal(); !ok {
		return fmt.Errorf("insufficient commits for reveal: %d", totalCommits)
	}
	reveal, err := instance.Reveal()
	if err != nil {
		return fmt.Errorf("failed to generate reveal: %w", err)
	}
	switch mode {
	case ModeBeaconHonest:
		revealPayload := beacon.PVSSReveal{
			Epoch:  state.Epoch,
			Round:  state.Round,
			Reveal: reveal,
		}
		tx := transaction.NewTransaction(0, nil, beacon.MethodPVSSReveal, revealPayload)
		if err = consensus.SignAndSubmitTx(ctx, b.tendermint.service, b.identity.NodeSigner, tx); err != nil {
			return fmt.Errorf("failed to submit reveal tx: %w", err)
		}
	default:
		logger.Debug("skipping reveal")
		shouldBeBad = true
	}

	// Wait for successful beacon generation
	if state, err = waitForBeaconState(ctx, backend, ch, beacon.StateComplete, true); err != nil {
		return fmt.Errorf("failed to wait on StateComplete: %w", err)
	}
	if isBad := state.BadParticipants[b.identity.NodeSigner.Public()]; isBad != shouldBeBad {
		return fmt.Errorf("unexpected bad participant status after reveal: %v", isBad)
	}

	return nil
}

func waitForBeaconState(
	ctx context.Context,
	backend beacon.PVSSBackend,
	ch <-chan *beacon.PVSSEvent,
	state beacon.RoundState,
	strict bool,
) (*beacon.PVSSState, error) {
	logger.Debug("beacon: waiting on state",
		"target", state,
	)

	for {
		ev, ok := <-ch
		if !ok {
			return nil, fmt.Errorf("event channel closed")
		}
		if ev.State != state {
			if strict {
				return nil, fmt.Errorf("unexpected state transition: %s (expected %s)", ev.State, state)
			}
			continue
		}

		state, err := backend.GetPVSSState(ctx, ev.Height)
		if err != nil {
			return nil, fmt.Errorf("failed to query PVSS state: %w", err)
		}

		return state, nil
	}
}
