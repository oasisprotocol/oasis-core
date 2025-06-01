package checkpoint

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	chunksDir              = "chunks"
	checkpointMetadataFile = "meta"
	checkpointV1           = 1
	checkpointV2           = 2

	// Versions 1 of checkpoint chunks use proofs version 0. Consider bumping
	// this to latest version when introducing new checkpoint versions.
	checkpointProofsVersion = 0
)

type fileCreatorV1 struct {
	dataDir string
	ndb     db.NodeDB
}

func (fc *fileCreatorV1) CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (meta *Metadata, err error) {
	tree := mkvs.NewWithRoot(nil, fc.ndb, root)
	defer tree.Close()

	// Create checkpoint directory.
	checkpointDir := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Version, 10),
		root.Hash.String(),
	)
	if err = common.Mkdir(checkpointDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint directory: %w", err)
	}
	defer func() {
		if err != nil {
			// In case we have failed to create a checkpoint, make sure to clean up after ourselves.
			_ = os.RemoveAll(checkpointDir)
		}
	}()

	// Check if the checkpoint already exists and just return the existing metadata in this case.
	data, err := os.ReadFile(filepath.Join(checkpointDir, checkpointMetadataFile))
	if err == nil {
		var existing Metadata
		if err = cbor.Unmarshal(data, &existing); err != nil {
			return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata: %w", err)
		}
		return &existing, nil
	}

	// Create chunks directory.
	chunksDir := filepath.Join(checkpointDir, chunksDir)
	if err = common.Mkdir(chunksDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create chunk directory: %w", err)
	}

	// Create chunks until we are done.
	var chunks []hash.Hash
	var nextOffset node.Key
	for chunkIndex := 0; ; chunkIndex++ {
		dataFilename := filepath.Join(chunksDir, strconv.Itoa(chunkIndex))

		// Generate chunk.
		var f *os.File
		if f, err = os.Create(dataFilename); err != nil {
			return nil, fmt.Errorf("checkpoint: failed to create chunk file for chunk %d: %w", chunkIndex, err)
		}

		var chunkHash hash.Hash
		chunkHash, nextOffset, err = createChunkV1(ctx, tree, root, nextOffset, chunkSize, f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("checkpoint: failed to create chunk %d: %w", chunkIndex, err)
		}

		chunks = append(chunks, chunkHash)

		// Check if we are finished.
		if nextOffset == nil {
			break
		}
	}

	// Generate and write checkpoint metadata.
	meta = &Metadata{
		Version: checkpointV1,
		Root:    root,
		Chunks:  chunks,
	}

	if err = os.WriteFile(filepath.Join(checkpointDir, checkpointMetadataFile), cbor.Marshal(meta), 0o600); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint metadata: %w", err)
	}
	return meta, nil
}

func (fc *fileCreatorV1) GetCheckpoints(_ context.Context, request *GetCheckpointsRequest) ([]*Metadata, error) {
	// Currently we only support two versions so we report no checkpoints for other versions.
	if request.Version != checkpointV1 && request.Version != checkpointV2 {
		return []*Metadata{}, nil
	}

	// Apply optional root version filter.
	versionGlob := "*"
	if request.RootVersion != nil {
		versionGlob = strconv.FormatUint(*request.RootVersion, 10)
	}

	matches, err := filepath.Glob(filepath.Join(fc.dataDir, versionGlob, "*", checkpointMetadataFile))
	if err != nil {
		return nil, fmt.Errorf("checkpoint: failed to enumerate checkpoints: %w", err)
	}

	var cps []*Metadata
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			return nil, fmt.Errorf("checkpoint: failed to read checkpoint metadata at %s: %w", m, err)
		}

		var cp Metadata
		if err = cbor.Unmarshal(data, &cp); err != nil {
			return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata at %s: %w", m, err)
		}

		cps = append(cps, &cp)
	}
	return cps, nil
}

func (fc *fileCreatorV1) GetCheckpoint(_ context.Context, version uint16, root node.Root) (*Metadata, error) {
	// Currently we only support two versions.
	if version != checkpointV1 && version != checkpointV2 {
		return nil, ErrCheckpointNotFound
	}

	checkpointFilename := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Version, 10),
		root.Hash.String(),
		checkpointMetadataFile,
	)
	data, err := os.ReadFile(checkpointFilename)
	if err != nil {
		return nil, ErrCheckpointNotFound
	}

	var cp Metadata
	if err = cbor.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata: %w", err)
	}
	return &cp, nil
}

func (fc *fileCreatorV1) DeleteCheckpoint(_ context.Context, version uint16, root node.Root) error {
	// Currently we only support two versions.
	if version != checkpointV1 && version != checkpointV2 {
		return ErrCheckpointNotFound
	}

	versionDir := filepath.Join(fc.dataDir, strconv.FormatUint(root.Version, 10))
	checkpointDir := filepath.Join(versionDir, root.Hash.String())
	checkpointFilename := filepath.Join(checkpointDir, checkpointMetadataFile)
	if err := os.Remove(checkpointFilename); err != nil {
		return ErrCheckpointNotFound
	}

	if err := os.RemoveAll(checkpointDir); err != nil {
		return fmt.Errorf("checkpoint: failed to remove checkpoint directory: %w", err)
	}

	// If there are no more roots for the given version, remove the version directory as well.
	f, err := os.Open(versionDir)
	if err != nil {
		return fmt.Errorf("checkpoint: failed to open directory: %w", err)
	}
	defer f.Close()

	switch _, err = f.Readdir(1); err {
	case nil:
		// Non-empty directory.
	case io.EOF:
		// Directory is empty, we can remove it.
		if err = os.RemoveAll(versionDir); err != nil {
			return fmt.Errorf("checkpoint: failed to remove version %d directory: %w", root.Version, err)
		}
	default:
		return fmt.Errorf("checkpoint: failed to read directory: %w", err)
	}

	return nil
}

func (fc *fileCreatorV1) GetCheckpointChunk(_ context.Context, chunk *ChunkMetadata, w io.Writer) error {
	// Currently we only support two versions.
	if chunk.Version != checkpointV1 && chunk.Version != checkpointV2 {
		return ErrChunkNotFound
	}

	chunkFilename := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(chunk.Root.Version, 10),
		chunk.Root.Hash.String(),
		chunksDir,
		strconv.FormatUint(chunk.Index, 10),
	)

	f, err := os.Open(chunkFilename)
	if err != nil {
		return ErrChunkNotFound
	}
	defer f.Close()

	if _, err = io.Copy(w, f); err != nil {
		return fmt.Errorf("checkpoint: failed to read chunk: %w", err)
	}
	return nil
}

// NewFileCreatorV1 creates a new checkpoint creator that writes created chunks into the filesystem.
func NewFileCreatorV1(dataDir string, ndb db.NodeDB) (Creator, error) {
	return &fileCreatorV1{
		dataDir: dataDir,
		ndb:     ndb,
	}, nil
}

type fileCreatorV2 struct {
	dataDir string
	ndb     db.NodeDB
}

// This is first iteration of CreateCheckpoint that should produce exactly equal checkpoint as V1.
// Internally instead of relying on Iterator for preparing proofs we build them manually.
//
// Next iteration is to use more compact V1 proofs.
// Final iteration is to dynamically parallelize and generate proofs/chunks in parallel.
func (fc *fileCreatorV2) CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (meta *Metadata, err error) {
	// Create checkpoint directory.
	checkpointDir := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Version, 10),
		root.Hash.String(),
	)
	if err = common.Mkdir(checkpointDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint directory: %w", err)
	}
	defer func() {
		if err != nil {
			// In case we have failed to create a checkpoint, make sure to clean up after ourselves.
			_ = os.RemoveAll(checkpointDir)
		}
	}()

	// Check if the checkpoint already exists and just return the existing metadata in this case.
	data, err := os.ReadFile(filepath.Join(checkpointDir, checkpointMetadataFile))
	if err == nil {
		var existing Metadata
		if err = cbor.Unmarshal(data, &existing); err != nil {
			return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata: %w", err)
		}
		return &existing, nil
	}

	// Create chunks directory.
	chunksDir := filepath.Join(checkpointDir, chunksDir)
	if err = common.Mkdir(chunksDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create chunk directory: %w", err)
	}

	// Create chunks.
	chunks, err := createChunksV2(ctx, fc.ndb, chunkSize, root, chunksDir, 15)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create chunks: %w", err)
	}

	// Generate and write checkpoint metadata.
	meta = &Metadata{
		Version: checkpointV1,
		Root:    root,
		Chunks:  chunks,
	}

	if err = os.WriteFile(filepath.Join(checkpointDir, checkpointMetadataFile), cbor.Marshal(meta), 0o600); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint metadata: %w", err)
	}
	return meta, nil
}

func (fc *fileCreatorV2) GetCheckpoint(ctx context.Context, version uint16, root node.Root) (*Metadata, error) {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.GetCheckpoint(ctx, version, root)
}

func (fc *fileCreatorV2) DeleteCheckpoint(ctx context.Context, version uint16, root node.Root) error {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.DeleteCheckpoint(ctx, version, root)
}

func (fc *fileCreatorV2) GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Metadata, error) {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.GetCheckpoints(ctx, request)
}

func (fc *fileCreatorV2) GetCheckpointChunk(ctx context.Context, chunk *ChunkMetadata, w io.Writer) error {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.GetCheckpointChunk(ctx, chunk, w)
}

// NewFileCreatorV2 creates a new checkpoint creator that writes created chunks into the filesystem.
func NewFileCreatorV2(dataDir string, ndb db.NodeDB) (Creator, error) {
	return &fileCreatorV2{
		dataDir: dataDir,
		ndb:     ndb,
	}, nil
}

type chunkCreator struct {
}

type visitState uint8

const (
	visitBefore visitState = iota
	visitAt
	visitAtLeft
	visitAfter
)

type pathAtom struct {
	nd    node.Node
	state visitState
}

// chunkTask is a task of creating a chunk in a given subtree,
// that may have been partially chunked already.
type chunkTask struct {
	ndb   db.NodeDB
	root  node.Root
	cache map[hash.Hash]node.Node
	// path is a path from root to subroot.
	path []node.Node
	// state is a state of subtree chunking.
	state []pathAtom
	idx   int
	// res is a hash of latest chunk created.
	res hash.Hash
	err error
}

func newTask(ctx context.Context, ndb db.NodeDB, root node.Root) (*chunkTask, error) {
	rootPtr := node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	}
	rootNode, err := ndb.GetNode(root, &rootPtr)
	if err != nil {
		return nil, fmt.Errorf("getting node from nodedb (hash: %.8s): %w", rootPtr.Hash, err)
	}

	initState := []pathAtom{
		{nd: rootNode, state: visitBefore},
	}

	return &chunkTask{
		ndb:   ndb,
		root:  root,
		state: initState,
	}, nil
}

func (ct *chunkTask) process(ctx context.Context, chunkSize uint64, chunksDir string) {
	dataFilename := filepath.Join(chunksDir, strconv.Itoa(ct.idx))
	f, err := os.Create(dataFilename)
	if err != nil {
		ct.err = err
		return
	}
	defer f.Close()

	ct.create(ctx, f, chunkSize)
}

func (ct *chunkTask) create(ctx context.Context, w io.Writer, chunkSize uint64) {
	defer func() {
		ct.trim()
	}()

	if ct.root.Hash.IsEmpty() { // TODO
		ct.err = fmt.Errorf("failed to create chunk for empty root")
		return
	}

	pb := syncer.NewProofBuilderV0(ct.root.Hash, ct.root.Hash)
	for _, nd := range ct.path {
		pb.Include(nd)
	}
	for _, pa := range ct.state { // Consider checking this does not overflow proof size already
		pb.Include(pa.nd)
	}

	var lastIsLeaf bool
	for len(ct.state) > 0 {
		select {
		case <-ctx.Done():
			ct.err = ctx.Err()
			return
		default:
		}

		if pb.Size() >= chunkSize && lastIsLeaf {
			ct.res, ct.err = createChunkV2(ctx, pb, w)
			return
		}

		current := ct.state[len(ct.state)-1]
		ct.state = ct.state[:len(ct.state)-1]

		switch currNode := current.nd.(type) {
		case nil:
			continue
		case *node.LeafNode:
			pb.Include(currNode)
			lastIsLeaf = true
		case *node.InternalNode:
			visitNext := func(ptr *node.Pointer) error {
				if ptr != nil {
					nd, err := ct.fetchNodeFromCacheOrDB(ptr)
					if err != nil {
						return fmt.Errorf("fetching node from cache or ndb (ptr hash: %.8s): %w", ptr.Hash, err)
					}
					ct.state = append(ct.state, pathAtom{nd, visitBefore})
				}
				return nil
			}
			switch current.state {
			case visitBefore:
				pb.Include(currNode)
				if currNode.LeafNode != nil {
					lastIsLeaf = true
				} else {
					lastIsLeaf = false
				}
				ct.state = append(ct.state, pathAtom{currNode, visitAt})
			case visitAt:
				ct.state = append(ct.state, pathAtom{currNode, visitAtLeft})
				if err := visitNext(currNode.Left); err != nil {
					ct.err = err
					return
				}
			case visitAtLeft:
				ct.state = append(ct.state, pathAtom{currNode, visitAfter})
				if err := visitNext(currNode.Right); err != nil {
					ct.err = err
					return
				}
			case visitAfter:
				continue
			default:
				ct.err = fmt.Errorf("unexpected atom state")
				return
			}
		default:
			ct.err = fmt.Errorf("unexpected node type")
			return
		}
	}

	if pb.Size() > 0 {
		ct.res, ct.err = createChunkV2(ctx, pb, w)
	} else {
		ct.err = fmt.Errorf("no nodes were included in final chunk")
	}
	return
}

func (ct *chunkTask) fetchNodeFromCacheOrDB(ptr *node.Pointer) (node.Node, error) {
	if nd, ok := ct.cache[ptr.Hash]; ok {
		return nd, nil
	}

	for h := range ct.cache {
		delete(ct.cache, h)
	}

	ct.cache, ct.err = ct.ndb.GetNodes(ct.root, ptr, 100)
	if ct.err != nil {
		return nil, fmt.Errorf("prefetching 1000 nodes: %w", ct.err)
	}

	return ct.cache[ptr.Hash], nil
}

func (ct *chunkTask) isFinished() bool {
	ct.trim()
	return len(ct.state) == 0
}

func (ct *chunkTask) trim() {
	for len(ct.state) > 0 && ct.state[len(ct.state)-1].state == visitAfter {
		ct.state = ct.state[:len(ct.state)-1]
	}
}

func copySlice[T any](s []T) []T {
	return append([]T{}, s...)
}

func (ct *chunkTask) split(ctx context.Context) ([]*chunkTask, error) {
	if ct.isFinished() {
		return nil, nil
	}

	first := ct.state[0]
	nd, ok := first.nd.(*node.InternalNode)
	if !ok {
		return nil, fmt.Errorf("unexpected type")
	}

	var tasks []*chunkTask
	addTask := func(ptr *node.Pointer, parent node.Node) error {
		if ptr == nil {
			return nil
		}

		nd, err := ct.ndb.GetNode(ct.root, ptr)
		if err != nil {
			return err
		}

		pathCopy := append([]node.Node(nil), ct.path...)
		task := &chunkTask{
			ndb:  ct.ndb,
			root: ct.root,
			path: append(pathCopy, parent),
			state: []pathAtom{
				{
					nd:    nd,
					state: visitBefore,
				},
			},
		}

		tasks = append(tasks, task)
		return nil
	}

	switch first.state {
	case visitBefore, visitAt:
		if nd.Left == nil && nd.Right == nil {
			return []*chunkTask{ct}, nil
		}
		if err := addTask(nd.Left, nd); err != nil {
			return nil, err
		}
		if err := addTask(nd.Right, nd); err != nil {
			return nil, err
		}
	case visitAtLeft:
		if len(ct.state) == 1 {
			return []*chunkTask{ct}, nil
		}

		if err := addTask(nd.Right, nd); err != nil {
			return nil, err
		}
		ct.path = append(ct.path, nd)
		ct.state = ct.state[1:]

		// consider removing / sanity
		if !ct.isFinished() {
			tasks = append(tasks, ct)
		}
		if len(tasks) == 0 {
			panic("unexpected zero tasks")
		}
	case visitAfter:
		ct.path = append(ct.path, nd)
		ct.state = ct.state[1:] // since we trim len(ct.state) must be > 1.

		// consider removing / sanity
		if !ct.isFinished() {
			tasks = append(tasks, ct)
		}
		if len(tasks) == 0 {
			panic("unexpected zero tasks")
		}
	default:
		return nil, fmt.Errorf("unexpected state")
	}

	return tasks, nil
}

// TODO consider using V1 proofs so that checkpoints size is reduced.
func createChunksV2(ctx context.Context, ndb db.NodeDB, chunkSize uint64, root node.Root, chunksDir string, minThreads int) ([]hash.Hash, error) {
	if root.Hash.IsEmpty() {
		return []hash.Hash{}, nil
	}

	initTask, err := newTask(ctx, ndb, root)
	if err != nil {
		return nil, err
	}

	chunks := make(map[int]hash.Hash, 0)
	var chunkIndex int
	tasks := []*chunkTask{initTask}
	for len(tasks) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var wg sync.WaitGroup
		for _, task := range tasks {
			wg.Add(1)
			task.idx = chunkIndex
			chunkIndex++
			go func() {
				defer wg.Done()
				task.process(ctx, chunkSize, chunksDir)
			}()
		}
		wg.Wait()

		var newTasks []*chunkTask
		for _, task := range tasks {
			if task.err != nil {
				return nil, task.err
			}
			chunks[task.idx] = task.res
			if !task.isFinished() {
				task.err, task.res, task.idx = nil, hash.Hash{}, -1
				newTasks = append(newTasks, task)
			}
		}
		tasks = newTasks

		if len(tasks) < minThreads {
			newTasks = nil
			// TODO sort so that output is deterministic
			for _, task := range tasks {
				childTasks, err := task.split(ctx)
				if err != nil {
					return nil, err
				}
				newTasks = append(newTasks, childTasks...)
			}
			tasks = newTasks
		}
	}

	hashes := make([]hash.Hash, 0, len(chunks))
	for i := 0; i < len(chunks); i++ {
		hashes = append(hashes, chunks[i])
	}

	return hashes, nil
}
