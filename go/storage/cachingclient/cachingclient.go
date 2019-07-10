// Package cachingclient implements a storage client wrapped with a
// disk-persisted in-memory local LRU cache.
package cachingclient

import (
	"context"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/storage/api"
	nodedb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	lrudb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/lru"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "cachingclient"

	// Path to file for persistent cache storage.
	cfgCacheFile = "storage.cachingclient.file"

	// Size of the cache in bytes.
	cfgCacheSize = "storage.cachingclient.cache_size"
)

var _ api.Backend = (*cachingClientBackend)(nil)
var _ api.ClientBackend = (*cachingClientBackend)(nil)

type cachingClientBackend struct {
	logger *logging.Logger

	remote    api.Backend
	local     nodedb.NodeDB
	rootCache *api.RootCache
}

func (b *cachingClientBackend) GetConnectedNodes() []*node.Node {
	if clientBackend, ok := b.remote.(api.ClientBackend); ok {
		return clientBackend.GetConnectedNodes()
	}
	return []*node.Node{}
}

func (b *cachingClientBackend) WatchRuntime(id signature.PublicKey) error {
	if clientBackend, ok := b.remote.(api.ClientBackend); ok {
		return clientBackend.WatchRuntime(id)
	}
	b.logger.Warn("cachingclient not watching runtime since remote is not ClientBackend")
	return errors.New("storage/cachingclient: remote note ClientBackend")
}

func (b *cachingClientBackend) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog api.WriteLog,
) ([]*api.Receipt, error) {
	// Apply to both local and remote DB.
	_, _ = b.rootCache.Apply(ctx, ns, srcRound, srcRoot, dstRound, dstRoot, writeLog)

	return b.remote.Apply(ctx, ns, srcRound, srcRoot, dstRound, dstRoot, writeLog)
}

func (b *cachingClientBackend) ApplyBatch(
	ctx context.Context,
	ns common.Namespace,
	dstRound uint64,
	ops []api.ApplyOp,
) ([]*api.Receipt, error) {
	// Apply to both local and remote DB.
	for _, op := range ops {
		_, err := b.rootCache.Apply(ctx, ns, op.SrcRound, op.SrcRoot, dstRound, op.DstRoot, op.WriteLog)
		if err != nil {
			break
		}
	}

	return b.remote.ApplyBatch(ctx, ns, dstRound, ops)
}

func (b *cachingClientBackend) GetSubtree(ctx context.Context, root api.Root, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetSubtree(ctx, root, id, maxDepth)
}

func (b *cachingClientBackend) GetPath(ctx context.Context, root api.Root, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetPath(ctx, root, key, startDepth)
}

func (b *cachingClientBackend) GetNode(ctx context.Context, root api.Root, id api.NodeID) (api.Node, error) {
	tree, err := b.rootCache.GetTree(ctx, root)
	if err != nil {
		return nil, err
	}

	return tree.GetNode(ctx, root, id)
}

func (b *cachingClientBackend) GetDiff(ctx context.Context, startRoot api.Root, endRoot api.Root) (api.WriteLogIterator, error) {
	return b.remote.GetDiff(ctx, startRoot, endRoot)
}

func (b *cachingClientBackend) GetCheckpoint(ctx context.Context, root api.Root) (api.WriteLogIterator, error) {
	return b.remote.GetCheckpoint(ctx, root)
}

func (b *cachingClientBackend) HasRoot(root api.Root) bool {
	return b.rootCache.HasRoot(root)
}

func (b *cachingClientBackend) Cleanup() {
	b.remote.Cleanup()
	b.local.Close()
}

func (b *cachingClientBackend) Initialized() <-chan struct{} {
	return b.remote.Initialized()
}

func New(remote api.Backend, insecureSkipChecks bool) (api.Backend, error) {
	lruCacheSizeInBytes := uint64(viper.GetSizeInBytes(cfgCacheSize))
	lruFile := viper.GetString(cfgCacheFile)

	local, err := lrudb.New(lruCacheSizeInBytes, lruFile)
	if err != nil {
		return nil, err
	}

	rootCache, err := api.NewRootCache(local, remote, lruCacheSizeInBytes/8, 1000, insecureSkipChecks)
	if err != nil {
		local.Close()
		return nil, err
	}

	b := &cachingClientBackend{
		logger:    logging.GetLogger("storage/cachingclient"),
		remote:    remote,
		local:     local,
		rootCache: rootCache,
	}

	return b, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgCacheFile, "cachingclient.storage.file", "Path to file for persistent cache storage")
		cmd.Flags().String(cfgCacheSize, "512mb", "Cache size (bytes)")
	}

	for _, v := range []string{
		cfgCacheFile,
		cfgCacheSize,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
