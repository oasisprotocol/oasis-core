package storage

import (
	"context"
	"fmt"
	"io"

	fxcbor "github.com/fxamacker/cbor/v2"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	mkvsAPI "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const v1 = 1

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
	if end == 0 {
		return nil, fmt.Errorf("end version must be at least 1")
	}

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
	if meta.V != v1 {
		return nil, fmt.Errorf("unsupported metadata version: %d", meta.V)
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
