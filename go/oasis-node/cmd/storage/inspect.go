package storage

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

// Status contains results of inspecting all of the node's databases.
type Status struct {
	// Consensus is the consensus part of the status.
	Consensus ConsensusStatus `json:"consensus"`
	// Runtimes is the runtimes part of the status.
	Runtimes map[common.Namespace]RuntimeStatus `json:"runtimes"`
}

// ConsensusStatus summarizes the state of the consensus databases.
type ConsensusStatus struct {
	// StateDB is the status of the consensus state db (Merkelized key-value store).
	StateDB DBStatus `json:"state_db"`
	// BlockHistory is the status of the consensus block store.
	BlockHistory DBStatus `json:"block_history"`
}

// RuntimeStatus summarizes the state of the runtime databases.
type RuntimeStatus struct {
	// StateDB is the status of the runtime state db (Merkelized key-value store).
	StateDB DBStatus `json:"state_db"`
	// LightHistory is the status of the runtime light history.
	LightHistory DBStatus `json:"light_history"`
}

// DBStatus is a database status.
type DBStatus struct {
	// Ok is true when the db exists and there was no error inspecting it.
	Ok bool `json:"ok"`
	// LatestVersion is the version of the most recent item stored in the corresponding db.
	LatestVersion uint64 `json:"latest_version"`
	// LastRetainedVersion is the version of the oldest item stored in the corresponding db.
	LastRetainedVersion uint64 `json:"last_retained_version"`
}

// Inspect inspects node's databases and returns a corresponding storage Status.
//
// The node should not be running once this command is called.
func Inspect(ctx context.Context, dataDir string, runtimes []common.Namespace) Status {
	var status Status
	status.Runtimes = make(map[common.Namespace]RuntimeStatus)

	func() {
		ndb, close, err := openConsensusNodeDB(dataDir)
		if err != nil {
			logger.Error("failed to open consensus NodeDB", "err", err)
			return
		}
		defer close()
		status.Consensus.StateDB.LatestVersion, status.Consensus.StateDB.Ok = ndb.GetLatestVersion()
		status.Consensus.StateDB.LastRetainedVersion = ndb.GetEarliestVersion()
	}()

	func() {
		blockstore, err := openConsensusBlockstore(dataDir)
		if err != nil {
			logger.Error("failed to open consensus blockstore", "err", err)
			return
		}
		defer blockstore.Close()
		status.Consensus.BlockHistory.Ok = true
		status.Consensus.BlockHistory.LatestVersion = uint64(blockstore.Height())
		status.Consensus.BlockHistory.LastRetainedVersion = uint64(blockstore.Base())
	}()

	for _, rt := range runtimes {
		var rtStatus RuntimeStatus

		func() {
			ndb, err := openRuntimeStateDB(dataDir, rt)
			if err != nil {
				logger.Error("failed to open runtime state DB", "err", err)
				return
			}
			defer ndb.Close()
			rtStatus.StateDB.LatestVersion, rtStatus.StateDB.Ok = ndb.GetLatestVersion()
			rtStatus.StateDB.LastRetainedVersion = ndb.GetEarliestVersion()
		}()

		func() {
			history, err := openRuntimeLightHistory(dataDir, rt)
			if err != nil {
				logger.Error("failed to open light history", "err", err)
				return
			}
			defer history.Close()

			latest, err := history.GetCommittedBlock(ctx, roothash.RoundLatest)
			if err != nil {
				logger.Error("failed to get latest light history block", "err", err)
				return
			}
			rtStatus.LightHistory.LatestVersion = latest.Header.Round
			earliest, err := history.GetEarliestBlock(ctx)
			if err != nil {
				logger.Error("failed to get earliest light history block", "err", err)
				return
			}
			rtStatus.LightHistory.LastRetainedVersion = earliest.Header.Round
			rtStatus.LightHistory.Ok = true
		}()

		status.Runtimes[rt] = rtStatus
	}

	return status
}

func newInspectCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "inspect storage",
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := cmdCommon.Init(); err != nil {
				cmdCommon.EarlyLogAndExit(err)
			}

			running, err := cmdCommon.IsNodeRunning()
			if err != nil {
				return fmt.Errorf("failed to ensure the node is not running: %w", err)
			}
			if running {
				return fmt.Errorf("node is running")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			runtimes, err := registry.GetConfiguredRuntimeIDs()
			if err != nil {
				return fmt.Errorf("failed to get configured runtimes: %w", err)
			}
			status := Inspect(cmd.Context(), cmdCommon.DataDir(), runtimes)

			switch outputFormat {
			case "json":
				prettyStatus, err := cmdCommon.PrettyJSONMarshal(status)
				if err != nil {
					return fmt.Errorf("failed to marshal status as JSON: %w", err)
				}
				fmt.Println(string(prettyStatus))
				return nil
			case "text", "":
				// Fall through to text output.
			default:
				return fmt.Errorf("unsupported output format: %s (supported: text, json)", outputFormat)
			}

			fmt.Println("Consensus:")
			fmt.Println("  State DB:")
			fmt.Println("    Ok: ", status.Consensus.StateDB.Ok)
			fmt.Println("    Latest height: ", status.Consensus.StateDB.LatestVersion)
			fmt.Println("    Last retained height: ", status.Consensus.StateDB.LastRetainedVersion)
			fmt.Println("  Block history:")
			fmt.Println("    Ok: ", status.Consensus.BlockHistory.Ok)
			fmt.Println("    Latest height: ", status.Consensus.BlockHistory.LatestVersion)
			fmt.Println("    Last retained height: ", status.Consensus.BlockHistory.LastRetainedVersion)

			if len(status.Runtimes) == 0 {
				return nil
			}

			fmt.Println("Runtimes:")
			for rt, rtStatus := range status.Runtimes {
				fmt.Println(" ", rt)
				fmt.Println("    State DB:")
				fmt.Println("      Ok: ", rtStatus.StateDB.Ok)
				fmt.Println("      Latest round: ", rtStatus.StateDB.LatestVersion)
				fmt.Println("      Last retained round: ", rtStatus.StateDB.LastRetainedVersion)
				fmt.Println("    Light History:")
				fmt.Println("      Ok: ", rtStatus.LightHistory.Ok)
				fmt.Println("      Latest round: ", rtStatus.LightHistory.LatestVersion)
				fmt.Println("      Last retained round: ", rtStatus.LightHistory.LastRetainedVersion)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&outputFormat, "output", "text", "output format (text, json)")

	return cmd
}
