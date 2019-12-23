package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdConsensus "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/consensus"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	"github.com/oasislabs/oasis-core/go/storage"
	storageAPI "github.com/oasislabs/oasis-core/go/storage/api"
	storageClient "github.com/oasislabs/oasis-core/go/storage/client"
	storageDatabase "github.com/oasislabs/oasis-core/go/storage/database"
)

const cfgExportDir = "storage.export.dir"

var (
	storageExportCmd = &cobra.Command{
		Use:   "export",
		Short: "export the storage roots contained in a state dump",
		Run:   doExport,
	}

	storageExportFlags = flag.NewFlagSet("", flag.ContinueOnError)
)

func doExport(cmd *cobra.Command, args []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("data directory must be set")
		return
	}

	destDir := viper.GetString(cfgExportDir)
	if destDir == "" {
		destDir = dataDir
	} else if err := common.Mkdir(destDir); err != nil {
		logger.Error("failed to create destination directory",
			"err", err,
			"dir", destDir,
		)
		return
	}

	// Load the genesis document.
	genesisDoc := cmdConsensus.InitGenesis()

	// For each storage root.
	for runtimeID, rtg := range genesisDoc.RootHash.RuntimeStates {
		logger.Info("fetching checkpoint write log",
			"runtime_id", runtimeID,
		)

		if err := exportRuntime(dataDir, destDir, runtimeID, rtg); err != nil {
			return
		}
	}

	ok = true
}

func exportRuntime(dataDir, destDir string, id signature.PublicKey, rtg *registry.RuntimeGenesis) error {
	dataDir = filepath.Join(dataDir, runtimeRegistry.RuntimesDir, id.String())

	// Initialize the storage backend.
	var ns common.Namespace
	_ = ns.UnmarshalBinary(id[:])

	storageBackend, err := newDirectStorageBackend(dataDir, ns)
	if err != nil {
		logger.Error("failed to construct storage backend",
			"err", err,
		)
		return err
	}

	logger.Info("waiting for storage backend initialization")
	<-storageBackend.Initialized()
	defer storageBackend.Cleanup()

	// Get the checkpoint iterator.
	root := storageAPI.Root{
		Namespace: ns,
		Round:     rtg.Round,
		Hash:      rtg.StateRoot,
	}
	it, err := storageBackend.GetCheckpoint(context.Background(),
		&storageAPI.GetCheckpointRequest{
			Root: root,
		},
	)
	if err != nil {
		logger.Error("failed getting checkpoint",
			"err", err,
			"namespace", root.Namespace,
			"round", root.Round,
			"root", root.Hash,
		)
		return err
	}

	fn := fmt.Sprintf("storage-dump-%v-%d.json",
		root.Namespace.String(),
		root.Round,
	)
	fn = filepath.Join(destDir, fn)
	return exportIterator(fn, &root, it)
}

func exportIterator(fn string, root *storageAPI.Root, it storageAPI.WriteLogIterator) error {
	// Create the dump file, and initialize a JSON stream encoder.
	f, err := os.Create(fn)
	if err != nil {
		logger.Error("failed to create dump file",
			"err", err,
			"fn", fn,
		)
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	enc := json.NewEncoder(w)

	// Dump the root.
	if err = enc.Encode(root); err != nil {
		logger.Error("failed to encode checkpoint root",
			"err", err,
		)
		return err
	}

	// Dump the write log.
	for {
		more, err := it.Next()
		if err != nil {
			logger.Error("failed to fetch next item from write log iterator",
				"err", err,
			)
			return err
		}

		if !more {
			return nil
		}

		val, err := it.Value()
		if err != nil {
			logger.Error("failed to get value from write log iterator",
				"err", err,
			)
			return err
		}

		if err = enc.Encode([][]byte{val.Key, val.Value}); err != nil {
			logger.Error("failed to encode write log entry",
				"err", err,
			)
			return err
		}
	}
}

func newDirectStorageBackend(dataDir string, namespace common.Namespace) (storageAPI.Backend, error) {
	// The right thing to do will be to use storage.New, but the backend config
	// assumes that identity is valid, and we don't have one.
	cfg := &storageAPI.Config{
		Backend:           strings.ToLower(viper.GetString(storage.CfgBackend)),
		DB:                dataDir,
		ApplyLockLRUSlots: uint64(viper.GetInt(storage.CfgLRUSlots)),
		Namespace:         namespace,
	}

	b := strings.ToLower(viper.GetString(storage.CfgBackend))
	switch b {
	case storageDatabase.BackendNameBadgerDB:
		cfg.DB = filepath.Join(cfg.DB, storageDatabase.DefaultFileName(cfg.Backend))
		return storageDatabase.New(cfg)
	case storageClient.BackendName:
		return storageClient.New(context.Background(), namespace, nil, nil, nil)
	default:
		return nil, fmt.Errorf("storage: unsupported backend: '%v'", cfg.Backend)
	}
}

func init() {
	storageExportFlags.String(cfgExportDir, "", "the destination directory for storage dumps")
	_ = viper.BindPFlags(storageExportFlags)
}
