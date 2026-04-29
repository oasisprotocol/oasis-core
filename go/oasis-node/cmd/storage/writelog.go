package storage

import (
	"context"
	"fmt"
	"io"
	"os"

	fxcbor "github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	mkvsAPI "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	v1             = 1
	autoEndVersion = ^uint64(0)
)

type writeLogMetadata struct {
	cbor.Versioned

	// Start is the version that the first serialized write log produces.
	Start uint64 `json:"start"`
	// End is the version that the last serialized write log produces.
	End uint64 `json:"end"`
}

type versionRoots struct {
	state node.Root
	io    node.Root
}

type writeLogExporter struct {
	ndb          mkvsAPI.NodeDB
	ns           common.Namespace
	encoder      *fxcbor.Encoder
	prevRoots    versionRoots
	startVersion uint64
	endVersion   uint64
}

// newWriteLogExporter creates an exporter that will serialize write logs for versions
// in the inclusive range [start, end], to provided writer w.
func newWriteLogExporter(ndb mkvsAPI.NodeDB, ns common.Namespace, start, end uint64, w io.Writer) (*writeLogExporter, error) {
	if start == 0 {
		return nil, fmt.Errorf("start version must be at least 1")
	}
	if start >= end {
		return nil, fmt.Errorf("start version greater or equal than end version")
	}

	latest, ok := ndb.GetLatestVersion()
	if !ok {
		return nil, fmt.Errorf("empty state DB")
	}
	if latest < end {
		return nil, fmt.Errorf("latest version lower than requested end version")
	}

	earliest := ndb.GetEarliestVersion()
	if start <= earliest {
		return nil, fmt.Errorf("start version not higher than earliest version")
	}

	prevRoots, err := getRoots(ndb, ns, start-1)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve roots for version %d: %w", start-1, err)
	}

	return &writeLogExporter{
		ndb:          ndb,
		ns:           ns,
		encoder:      cbor.NewEncoder(w),
		prevRoots:    prevRoots,
		startVersion: start,
		endVersion:   end,
	}, nil
}

func (w *writeLogExporter) export(ctx context.Context) error {
	if err := w.encoder.Encode(writeLogMetadata{
		Versioned: cbor.NewVersioned(v1),
		Start:     w.startVersion,
		End:       w.endVersion,
	}); err != nil {
		return fmt.Errorf("failed to encode metadata: %w", err)
	}

	for version := w.startVersion; version <= w.endVersion; version++ {
		roots, err := getRoots(w.ndb, w.ns, version)
		if err != nil {
			return fmt.Errorf("failed to resolve roots for version %d: %w", version, err)
		}

		stateWl, err := getWriteLog(ctx, w.ndb, w.prevRoots.state, roots.state)
		if err != nil {
			return fmt.Errorf("failed to fetch state write log for version %d: %w", version, err)
		}
		if err = w.encoder.Encode(stateWl); err != nil {
			return fmt.Errorf("failed to encode state write log for version %d: %w", version, err)
		}

		emptyIO := makeEmptyRoot(roots.state.Namespace, version, node.RootTypeIO) // IO roots are not chained.
		ioWl, err := getWriteLog(ctx, w.ndb, emptyIO, roots.io)
		if err != nil {
			return fmt.Errorf("failed to fetch io write log for version %d: %w", version, err)
		}
		if err = w.encoder.Encode(ioWl); err != nil {
			return fmt.Errorf("failed to encode io write log for version %d: %w", version, err)
		}

		w.prevRoots = roots
	}

	return nil
}

func getRoots(ndb mkvsAPI.NodeDB, ns common.Namespace, version uint64) (versionRoots, error) {
	roots, err := ndb.GetRootsForVersion(version)
	if err != nil {
		return versionRoots{}, err
	}

	var result versionRoots
	for _, root := range roots {
		switch root.Type {
		case node.RootTypeState:
			result.state = root
		case node.RootTypeIO:
			result.io = root
		}
	}

	// Missing roots imply implicitly present empty root.
	if result.state.Type != node.RootTypeState {
		result.state = makeEmptyRoot(ns, version, node.RootTypeState)
	}
	if result.io.Type != node.RootTypeIO {
		result.io = makeEmptyRoot(ns, version, node.RootTypeIO)
	}

	return result, nil
}

func makeEmptyRoot(namespace common.Namespace, version uint64, rootType node.RootType) node.Root {
	root := node.Root{
		Namespace: namespace,
		Version:   version,
		Type:      rootType,
	}
	root.Hash.Empty()
	return root
}

func getWriteLog(ctx context.Context, ndb mkvsAPI.NodeDB, startRoot, endRoot node.Root) (writelog.WriteLog, error) {
	if startRoot.Hash.Equal(&endRoot.Hash) {
		return writelog.WriteLog{}, nil
	}

	it, err := ndb.GetWriteLog(ctx, startRoot, endRoot)
	if err != nil {
		return nil, err
	}

	return collectWriteLog(it)
}

func collectWriteLog(it writelog.Iterator) (writelog.WriteLog, error) {
	var wl writelog.WriteLog
	for {
		ok, err := it.Next()
		if err != nil {
			return nil, err
		}
		if !ok {
			return wl, nil
		}

		entry, err := it.Value()
		if err != nil {
			return nil, err
		}
		wl = append(wl, entry)
	}
}

type trustedProvider interface {
	roots(ctx context.Context, version uint64) (versionRoots, error)
}

type historyTrustedRoots struct {
	history history.History
}

func (p historyTrustedRoots) roots(ctx context.Context, version uint64) (versionRoots, error) {
	blk, err := p.history.GetCommittedBlock(ctx, version)
	if err != nil {
		return versionRoots{}, err
	}

	var roots versionRoots
	for _, root := range blk.Header.StorageRoots() {
		switch root.Type {
		case node.RootTypeState:
			roots.state = root
		case node.RootTypeIO:
			roots.io = root
		}
	}

	return roots, nil
}

type writeLogImporter struct {
	ndb          mkvsAPI.NodeDB
	ns           common.Namespace
	provider     trustedProvider
	streamStart  uint64
	startVersion uint64
	endVersion   uint64
	rootCache    *storageAPI.RootCache
	decoder      *fxcbor.Decoder
}

// newWriteLogImporter creates an importer that will import write logs into the
// ndb, starting from the ndb latest finalized version and to end version inclusive.
//
// If the input stream spans a larger range than needed, only the required write logs will be imported.
func newWriteLogImporter(
	ndb mkvsAPI.NodeDB,
	ns common.Namespace,
	provider trustedProvider,
	end uint64,
	r io.Reader,
) (*writeLogImporter, error) {
	latest, ok := ndb.GetLatestVersion()
	startVersion := uint64(1)
	if ok {
		startVersion = latest + 1
	}

	decoder := cbor.NewDecoder(r)

	var meta writeLogMetadata
	if err := decoder.Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}
	if end == autoEndVersion {
		end = meta.End
	}
	if meta.V != v1 {
		return nil, fmt.Errorf("unsupported metadata version: %d", meta.V)
	}
	if meta.End == 0 {
		return nil, fmt.Errorf("metadata end version must be at least 1")
	}
	if meta.End < end {
		return nil, fmt.Errorf("metadata ends before requested end version")
	}
	if meta.Start > startVersion {
		return nil, fmt.Errorf("metadata starts after required start version")
	}

	rootCache, err := storageAPI.NewRootCache(ndb)
	if err != nil {
		return nil, fmt.Errorf("failed to create root cache: %w", err)
	}

	return &writeLogImporter{
		ndb:          ndb,
		ns:           ns,
		provider:     provider,
		streamStart:  meta.Start,
		startVersion: startVersion,
		endVersion:   end,
		rootCache:    rootCache,
		decoder:      decoder,
	}, nil
}

func (w *writeLogImporter) importUntrusted(ctx context.Context) error {
	prevRoots, err := getRoots(w.ndb, w.ns, w.startVersion-1)
	if err != nil {
		return fmt.Errorf("failed to resolve roots for version %d: %w", w.startVersion-1, err)
	}

	for version := w.streamStart; version <= w.endVersion; version++ {
		var stateWriteLog writelog.WriteLog
		if err := w.decoder.Decode(&stateWriteLog); err != nil {
			return fmt.Errorf("failed to decode state write log for version %d: %w", version, err)
		}

		var ioWriteLog writelog.WriteLog
		if err := w.decoder.Decode(&ioWriteLog); err != nil {
			return fmt.Errorf("failed to decode io write log for version %d: %w", version, err)
		}

		if version < w.startVersion {
			continue
		}

		trustedRoots, err := w.provider.roots(ctx, version)
		if err != nil {
			return fmt.Errorf("failed to get trusted roots for version %d: %w", version, err)
		}

		if _, err = w.rootCache.Apply(ctx, prevRoots.state, trustedRoots.state, stateWriteLog); err != nil {
			return fmt.Errorf("failed to apply state write log for version %d: %w", version, err)
		}

		emptyIO := makeEmptyRoot(trustedRoots.io.Namespace, trustedRoots.io.Version, node.RootTypeIO) // IO roots are not chained.
		if _, err = w.rootCache.Apply(ctx, emptyIO, trustedRoots.io, ioWriteLog); err != nil {
			return fmt.Errorf("failed to apply io write log for version %d: %w", version, err)
		}

		if err = w.ndb.Finalize([]node.Root{trustedRoots.state, trustedRoots.io}); err != nil {
			return fmt.Errorf("failed to finalize version %d: %w", version, err)
		}

		prevRoots = trustedRoots
	}

	return nil
}

func newWriteLogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "writelog",
		Short: "export and import storage write logs",
		PersistentPreRunE: func(_ *cobra.Command, args []string) error {
			if err := cmdCommon.Init(); err != nil {
				cmdCommon.EarlyLogAndExit(err)
			}
			running, err := cmdCommon.IsNodeRunning()
			if err != nil {
				return fmt.Errorf("failed to ensure the node is not running: %w", err)
			}
			if running {
				return fmt.Errorf("write log operations can only be done when the node is not running")
			}
			return nil
		},
	}

	cmd.AddCommand(newWriteLogExportCmd())
	cmd.AddCommand(newWriteLogImportCmd())

	return cmd
}

func newWriteLogExportCmd() *cobra.Command {
	var (
		runtimeID  string
		outputFile string
		start      uint64
		end        uint64
	)

	cmd := &cobra.Command{
		Use:   "export",
		Args:  cobra.NoArgs,
		Short: "export runtime storage write logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			dataDir := cmdCommon.DataDir()

			var ns common.Namespace
			if err := ns.UnmarshalHex(runtimeID); err != nil {
				return fmt.Errorf("malformed runtime ID: %q: %w", runtimeID, err)
			}

			ndb, err := openRuntimeStateDB(dataDir, ns)
			if err != nil {
				return fmt.Errorf("failed to open runtime state DB: %w", err)
			}
			defer ndb.Close()

			latest, ok := ndb.GetLatestVersion()
			if !ok {
				return fmt.Errorf("empty state DB")
			}
			earliest := ndb.GetEarliestVersion()

			if start == 0 {
				start = earliest + 1
			}
			if end == 0 {
				end = latest
			}

			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer f.Close()

			exporter, err := newWriteLogExporter(ndb, ns, start, end, f)
			if err != nil {
				return fmt.Errorf("failed to create write log exporter: %w", err)
			}
			if err = exporter.export(ctx); err != nil {
				return fmt.Errorf("failed to export write logs: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&runtimeID, "runtime", "", "hex encoded runtime ID")
	cmd.Flags().StringVar(&outputFile, "output-file", "", "output file")
	cmd.Flags().Uint64Var(&start, "start", 0, "first version to export (defaults to earliest + 1 version)")
	cmd.Flags().Uint64Var(&end, "end", 0, "last version to export (defaults to latest version)")
	_ = cmd.MarkFlagRequired("runtime")
	_ = cmd.MarkFlagRequired("output-file")

	return cmd
}

func newWriteLogImportCmd() *cobra.Command {
	var (
		runtimeID string
		inputFile string
		end       uint64 = autoEndVersion
	)

	cmd := &cobra.Command{
		Use:   "import",
		Args:  cobra.NoArgs,
		Short: "import runtime storage write logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			dataDir := cmdCommon.DataDir()

			var ns common.Namespace
			if err := ns.UnmarshalHex(runtimeID); err != nil {
				return fmt.Errorf("malformed runtime ID: %q: %w", runtimeID, err)
			}

			ndb, err := openRuntimeStateDB(dataDir, ns)
			if err != nil {
				return fmt.Errorf("failed to open runtime state DB: %w", err)
			}
			defer ndb.Close()

			h, err := openRuntimeLightHistory(dataDir, ns)
			if err != nil {
				return fmt.Errorf("failed to open runtime history: %w", err)
			}
			defer h.Close()

			f, err := os.Open(inputFile)
			if err != nil {
				return fmt.Errorf("failed to open input file: %w", err)
			}
			defer f.Close()

			importer, err := newWriteLogImporter(ndb, ns, historyTrustedRoots{history: h}, end, f)
			if err != nil {
				return fmt.Errorf("failed to create write log importer: %w", err)
			}
			if err = importer.importUntrusted(ctx); err != nil {
				return fmt.Errorf("failed to import write logs: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&runtimeID, "runtime", "", "hex encoded runtime ID")
	cmd.Flags().StringVar(&inputFile, "input-file", "", "input file")
	cmd.Flags().Uint64Var(&end, "end", autoEndVersion, "last version to import (defaults to the end of the stream)")
	_ = cmd.MarkFlagRequired("runtime")
	_ = cmd.MarkFlagRequired("input-file")

	return cmd
}
