package sync_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/p2p"
	p2pApi "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/checkpointsync"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/diffsync"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/sync"
)

var (
	chainContext = "test_chain_context"
	runtimeID    = common.NewTestNamespaceFromSeed([]byte("test namespace"), 0)
)

// TestStorageSync test interoperability of storage sync P2P protocols.
//
// For context storage sync protocol was split into two protocols that are
// semantically equivalent to the respective subset of the legacy protocol.
//
// This test checks for backward and forward compatibility between legacy
// and new clients, with respect to legacy and new protocol servers.
func TestStorageSync(t *testing.T) {
	require := require.New(t)

	dataDir, err := os.MkdirTemp("", "oasis-worker-storage-p2p-sync_test")
	require.NoError(err, "Failed to create a temporary directory")
	defer os.RemoveAll(dataDir)

	tests := []struct {
		name       string
		legacyHost bool
		peerKind   peerKind
		err        error
	}{
		{
			name:       "Legacy host client with legacy peer",
			legacyHost: true,
			peerKind:   legacy,
		},
		{
			name:       "Legacy host client with new peer (all protocols)",
			legacyHost: true,
			peerKind:   all,
		},
		{
			name:       "New host client with legacy peer",
			legacyHost: false,
			peerKind:   legacy,
		},
		{
			name:       "New host client with new peer (all protocols)",
			legacyHost: false,
			peerKind:   all,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			test(t, dataDir, tc.legacyHost, tc.peerKind)
		})
	}
}

func test(t *testing.T, dataDir string, legacyHost bool, peerKind peerKind) {
	backend := &backendMock{}

	peer1, clean1 := mustStartNewPeer(t, dataDir, 1, backend, none)
	defer clean1()

	peer2, clean2 := mustStartNewPeer(t, dataDir, 2, backend, peerKind)
	defer clean2()

	err := peer1.Host().Connect(context.Background(), peer.AddrInfo{
		ID:    peer2.Host().ID(),
		Addrs: peer2.Host().Addrs(),
	})
	require.NoError(t, err, "Connecting host to peer")

	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	switch legacyHost {
	case true:
		testLegacyHostClient(ctx, t, peer1, backend)
	default:
		testNewClients(ctx, t, peer1, backend)
	}
}

func testLegacyHostClient(ctx context.Context, t *testing.T, host p2pApi.Service, backend storageApi.Backend) {
	require := require.New(t)

	client := sync.NewClient(host, chainContext, runtimeID)
	time.Sleep(2 * time.Second)

	// Test diff part of the storagesync protocol.
	rsp, _, err := client.GetDiff(ctx, &sync.GetDiffRequest{})
	require.NoError(err, "Fetch storage diff from p2p")

	err = assertEqualGetDiffResponse(ctx, backend, rsp.WriteLog)
	require.NoError(err, "Assert expected storage diff response")

	// Test checkpoints part of the storagesync protocol.
	cps, err := client.GetCheckpoints(ctx, &sync.GetCheckpointsRequest{
		Version: 1,
	})
	require.NoError(err, "Fetch checkpoints from p2p")
	want, err := backend.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{
		Version:   1,
		Namespace: runtimeID,
	})
	require.NoError(err, "Fetch expected storage diff from backend")
	getMeta := func(cp *sync.Checkpoint) *checkpoint.Metadata { return cp.Metadata }
	err = assertEqualCheckpoints(cps, want, getMeta)
	require.NoError(err, "Assert expected checkpoints response")
}

func testNewClients(ctx context.Context, t *testing.T, host p2pApi.Service, backend storageApi.Backend) {
	require := require.New(t)

	// Test diff sync protocol.
	diffClient := diffsync.NewClient(host, chainContext, runtimeID)
	time.Sleep(2 * time.Second)
	rsp2, _, err := diffClient.GetDiff(ctx, &diffsync.GetDiffRequest{})
	require.NoError(err, "Fetch storage diff from p2p")
	err = assertEqualGetDiffResponse(ctx, backend, rsp2.WriteLog)
	require.NoError(err, "Assert expected storage diff response")

	// Test checkpoint sync protocol.
	cpsClient := checkpointsync.NewClient(host, chainContext, runtimeID)
	time.Sleep(2 * time.Second)
	cps, err := cpsClient.GetCheckpoints(ctx, &checkpointsync.GetCheckpointsRequest{
		Version: 1,
	})
	require.NoError(err, "Fetch checkpoints from p2p")
	want, err := backend.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{
		Version:   1,
		Namespace: runtimeID,
	})
	require.NoError(err, "Fetch expected storage diff from backend")
	getMeta := func(cp *checkpointsync.Checkpoint) *checkpoint.Metadata { return cp.Metadata }
	err = assertEqualCheckpoints(cps, want, getMeta)
	require.NoError(err, "Assert expected checkpoints response")
}

func assertEqualGetDiffResponse(ctx context.Context, backend storageApi.Backend, got storageApi.WriteLog) error {
	diff, err := backend.GetDiff(ctx, &storageApi.GetDiffRequest{})
	if err != nil {
		return fmt.Errorf("fetching expected storage diff from backend: %w", err)
	}

	want := make(storageApi.WriteLog, 0)
	for {
		next, err := diff.Next()
		if !next {
			break
		}
		if err != nil {
			return fmt.Errorf("writelog iterator next: %w", err)
		}
		val, err := diff.Value()
		if err != nil {
			return fmt.Errorf("writelog iterator value: %w", err)
		}
		want = append(want, val)
	}

	if !want.Equal(got) {
		return fmt.Errorf("writelog not equal")
	}
	return nil
}

func assertEqualCheckpoints[C any](cps []C, want []*checkpoint.Metadata, getMeta func(C) *checkpoint.Metadata) error {
	if len(cps) != len(want) {
		return fmt.Errorf("slice size not equal: got %d, want %d", len(cps), len(want))
	}
	for i, cp1 := range cps {
		if err := assertEqualCheckpointMeta(getMeta(cp1), want[i]); err != nil {
			return fmt.Errorf("checkpoints at index %d not equal: %w", i, err)
		}
	}
	return nil
}

func assertEqualCheckpointMeta(this, other *checkpoint.Metadata) error {
	if this.Version != other.Version {
		return fmt.Errorf("version not equal")
	}
	if this.Root != other.Root {
		return fmt.Errorf("root not equal")
	}
	if len(this.Chunks) != len(other.Chunks) {
		return fmt.Errorf("not equal number of chunks")
	}
	for i, x := range this.Chunks {
		if !x.Equal(&other.Chunks[i]) {
			return fmt.Errorf("chunk %d not equal", i)
		}
	}
	return nil
}

type peerKind int

const (
	legacy peerKind = iota
	all
	none
)

func mustStartNewPeer(t *testing.T, dataDir string, id int, backend storageApi.Backend, kind peerKind) (service p2pApi.Service, clean func()) {
	var err error
	var cleanups []func()
	clean = func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	defer func() {
		if err != nil {
			clean()
		}
	}()

	require := require.New(t)

	dataDir = path.Join(dataDir, strconv.Itoa(id))
	err = os.Mkdir(dataDir, 0o700)
	require.NoError(err, "Failed to create a temporary directory")
	cleanups = append(cleanups, func() { os.RemoveAll(dataDir) })

	identity, err := identity.LoadOrGenerate(dataDir, memory.NewFactory())
	require.NoError(err, "Failed to generate a new identity")

	store, err := persistent.NewCommonStore(dataDir)
	require.NoError(err, "Failed to generate persistent common store")
	cleanups = append(cleanups, func() { store.Close() })

	port, err := getAvailablePort()
	require.NoError(err)
	// Avoid this pattern. Ideally p2p service should be refactored to not use
	// global config.
	config.GlobalConfig.P2P.Port = uint16(port)

	p2p, err := p2p.New(identity, chainContext, store)
	require.NoError(err, "Failed to generate persistent common store")
	err = p2p.Start()
	require.NoError(err, "Failed to start P2P service")
	cleanups = append(cleanups, func() { p2p.Stop() })

	switch kind {
	case legacy:
		serverLegacy := sync.NewServer(chainContext, runtimeID, backend)
		p2p.RegisterProtocolServer(serverLegacy)
	case all:
		serverLegacy := sync.NewServer(chainContext, runtimeID, backend)
		p2p.RegisterProtocolServer(serverLegacy)
		diff := diffsync.NewServer(chainContext, runtimeID, backend)
		p2p.RegisterProtocolServer(diff)
		checkpoints := checkpointsync.NewServer(chainContext, runtimeID, backend)
		p2p.RegisterProtocolServer(checkpoints)
	case none:
	default:
		panic("peer kind not supported")
	}

	return p2p, clean
}

// getAvailablePort is only safe for testing, since we risk race between closing
// and re-binding returned port.
func getAvailablePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

type backendMock struct{}

func (bm *backendMock) SyncGet(context.Context, *syncer.GetRequest) (*syncer.ProofResponse, error) {
	panic("not supported")
}

func (bm *backendMock) SyncGetPrefixes(context.Context, *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	panic("not supported")
}

func (bm *backendMock) SyncIterate(context.Context, *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	panic("not supported")
}

func hashFromBytes(data []byte) hash.Hash {
	var hash hash.Hash
	hash.FromBytes(data)
	return hash
}

var (
	cpVersion uint16
	root      node.Root
	hash1     hash.Hash = hashFromBytes([]byte("hash1"))
	hash2     hash.Hash = hashFromBytes([]byte("hash2"))
)

func (bm *backendMock) GetCheckpoints(_ context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	cpVersion = request.Version
	root = node.Root{
		// Existing bug: storagesync p2p server does not set namespace, nor does checkpoint.ChunkProvider validates it.
		//               As a result empty namespace is always passed around, thus commenting Namespace field below.
		// Namespace: request.Namespace
		Version: 1,
		Type:    api.RootTypeState,
		Hash:    hashFromBytes([]byte("root has")),
	}
	cp := &checkpoint.Metadata{
		Version: cpVersion,
		Root:    root,
		Chunks:  []hash.Hash{hash1, hash2},
	}

	return []*checkpoint.Metadata{cp}, nil
}

func (bm *backendMock) GetCheckpointChunk(_ context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	if !chunk.Root.Equal(&root) || chunk.Version != cpVersion || chunk.Index > 1 {
		return fmt.Errorf("invalid chunk metadata")
	}

	switch chunk.Index {
	case 0:
		if !chunk.Digest.Equal(&hash1) {
			return fmt.Errorf("invalid chunk metada")
		}
		if _, err := w.Write([]byte("hash1")); err != nil {
			return err
		}
	case 1:
		if !chunk.Digest.Equal(&hash2) {
			return fmt.Errorf("invalid chunk metada")
		}
		if _, err := w.Write([]byte("hash2")); err != nil {
			return err
		}
	}

	return nil
}

func (bm *backendMock) GetDiff(_ context.Context, request *storageApi.GetDiffRequest) (storageApi.WriteLogIterator, error) {
	items := writelog.WriteLog{
		writelog.LogEntry{Key: []byte("startHash"), Value: []byte(request.StartRoot.Hash.String())},
		writelog.LogEntry{Key: []byte("endHash"), Value: []byte(request.EndRoot.Hash.String())},
	}
	return writelog.NewStaticIterator(items), nil
}

func (bm *backendMock) Cleanup() {
	panic("not supported")
}

func (bm *backendMock) Initialized() <-chan struct{} {
	panic("not supported")
}
