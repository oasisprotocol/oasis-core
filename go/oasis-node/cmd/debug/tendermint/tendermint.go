// Package tendermint implements the tendermint debug sub-commands.
package tendermint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/inspector"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
)

var (
	stateFilename string

	tmCmd = &cobra.Command{
		Use:   "tendermint",
		Short: "tendermint backend utilities",
	}

	tmDumpMuxStateCmd = &cobra.Command{
		Use:   "dump-abci-mux-state",
		Short: "dump ABCI mux state as JSON",
		Run:   doDumpMuxState,
	}
)

func doDumpMuxState(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	logger := logging.GetLogger("cmd/debug/tendermint/dump-abci-mux-state")

	state, err := inspector.OpenMuxState(stateFilename)
	if err != nil {
		logger.Error("failed to open ABCI mux state",
			"err", err,
		)
		return
	}
	defer state.Close()

	output := make(map[string]interface{})
	state.Tree().Iterate(func(key, value []byte) bool {
		// Try to decode as CBOR and if that fails, output as hex.
		var decoded interface{}
		if err = cbor.Unmarshal(value, &decoded); err != nil {
			decoded = hex.EncodeToString(value)
		}

		output[string(key)] = decoded
		return false
	})

	buf := bytes.NewBuffer(nil)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "   ")

	if err = enc.Encode(output); err != nil {
		logger.Error("failed to encode ABCI mux state",
			"err", err,
		)
		return
	}

	fmt.Printf("%s\n", buf.Bytes())
}

// Register registers the tendermint sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	tmDumpMuxStateCmd.Flags().StringVarP(&stateFilename, "state", "s", "abci-mux-state.bolt.db", "ABCI mux state file to dump")
	tmCmd.AddCommand(tmDumpMuxStateCmd)
	parentCmd.AddCommand(tmCmd)
}
