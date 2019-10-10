// Package storage implements the storage debug sub-commands.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	storageApi "github.com/oasislabs/ekiden/go/storage/api"
	storageDb "github.com/oasislabs/ekiden/go/storage/database"
)

const (
	cfgExportDbBackend = "database.backend"
	cfgExportDbPath    = "database.path"
	cfgExportNamespace = "namespace"
	cfgExportRound     = "round"
	cfgExportRoot      = "root"
)

var (
	storageExportCmd = &cobra.Command{
		Use:   "export",
		Short: "export specific storage roots",
		Run:   doExport,
	}

	// ExportFlags has the export command configuration flags.
	ExportFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

func doExport(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Create storage backend.
	cfg := &storageApi.Config{
		Backend: strings.ToLower(viper.GetString(cfgExportDbBackend)),
		DB:      viper.GetString(cfgExportDbPath),
	}
	backend, err := storageDb.New(cfg)
	if err != nil {
		logger.Error("failed to create storage backend",
			"err", err,
		)
		os.Exit(1)
	}

	// Determine what to export.
	var root storageApi.Root
	if err = root.Namespace.UnmarshalHex(viper.GetString(cfgExportNamespace)); err != nil {
		logger.Error("failed to unmarshal namespace",
			"err", err,
		)
		os.Exit(1)
	}

	if err = root.Hash.UnmarshalHex(viper.GetString(cfgExportRoot)); err != nil {
		logger.Error("failed to unmarshal root hash",
			"err", err,
		)
		os.Exit(1)
	}

	root.Round = viper.GetUint64(cfgExportRound)

	// Fetch checkpoint.
	it, err := backend.GetCheckpoint(context.Background(), root)
	if err != nil {
		logger.Error("failed to get checkpoint from storage",
			"err", err,
		)
		os.Exit(1)
	}

	// TODO: Consider iterative JSON encoding to avoid holding everything
	//       in memory before encoding.
	var wl storageApi.WriteLog
	for {
		more, err := it.Next()
		if !more {
			break
		}
		if err != nil {
			logger.Error("error while reading from storage",
				"err", err,
			)
			os.Exit(1)
		}

		entry, _ := it.Value()
		wl = append(wl, entry)
	}

	encoded, _ := json.Marshal(wl)
	fmt.Printf("%s\n", encoded)
}

func init() {
	ExportFlags.String(cfgExportDbBackend, "", "Database backend")
	ExportFlags.String(cfgExportDbPath, "", "Path to database file")
	ExportFlags.String(cfgExportNamespace, "", "Namespace to export")
	ExportFlags.Uint64(cfgExportRound, 0, "Round to export")
	ExportFlags.String(cfgExportRoot, "", "Root hash to export")

	_ = viper.BindPFlags(ExportFlags)
}
