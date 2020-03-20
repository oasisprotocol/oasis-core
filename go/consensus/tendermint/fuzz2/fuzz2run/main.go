// +build gofuzz

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/spf13/cobra"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/fuzz2"
)

var rootCmd = &cobra.Command{
	Use: "fuzz2run",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := logging.Initialize(os.Stdout, logging.FmtJSON, logging.LevelDebug, nil); err != nil {
			return fmt.Errorf("initialize logging: %w", err)
		}
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read data from stdin: %w", err)
		}
		rv := fuzz2.Fuzz(data)
		fmt.Printf("Fuzz returned %d\n", rv)
		return nil
	},
}

func main() {
	_ = rootCmd.Execute()
}
