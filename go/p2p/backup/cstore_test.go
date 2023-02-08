package backup

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/oasisprotocol/oasis-core/go/common/persistent"
)

type CommonStoreBackendTestSuite struct {
	suite.Suite

	dir     string
	store   *persistent.CommonStore
	backend Backend

	addrs []peer.AddrInfo
}

func TestCommonStoreBackendTestSuite(t *testing.T) {
	suite.Run(t, new(CommonStoreBackendTestSuite))
}

func (s *CommonStoreBackendTestSuite) SetupSuite() {
	require := require.New(s.T())

	var err error
	s.dir, err = os.MkdirTemp("", "oasis-p2p-backup-test_")
	require.NoError(err, "TempDir failed")

	s.store, err = persistent.NewCommonStore(s.dir)
	require.NoError(err, "NewCommonStore failed")

	s.backend = NewCommonStoreBackend(s.store, "bucket", "key")

	s.addrs = make([]peer.AddrInfo, 5)
	for i := 0; i < len(s.addrs); i++ {
		_, pk, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
		require.NoError(err, "GenerateKeyPair failed")

		id, err := peer.IDFromPublicKey(pk)
		require.NoError(err, "IDFromPublicKey failed")

		addr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/", 8000+i))
		require.NoError(err, "NewMultiaddr failed")

		s.addrs[i] = peer.AddrInfo{
			ID:    id,
			Addrs: []multiaddr.Multiaddr{addr},
		}
	}
}

func (s *CommonStoreBackendTestSuite) TearDownSuite() {
	require := require.New(s.T())

	if s.dir != "" {
		err := os.RemoveAll(s.dir)
		require.NoError(err, "RemoveAll failed")
	}
}

func (s *CommonStoreBackendTestSuite) TestDelete() {
	require := require.New(s.T())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peers := map[string][]peer.AddrInfo{
		"ns-1": {s.addrs[0], s.addrs[1], s.addrs[2]},
	}

	err := s.backend.Backup(ctx, peers)
	require.NoError(err, "Failed to backup peers")

	restored, err := s.backend.Restore(ctx)
	require.NoError(err, "Failed to restore peers")

	require.True(reflect.DeepEqual(peers, restored), "Restored peers to not match")

	err = s.backend.Delete(ctx)
	require.NoError(err, "Failed to delete the backup")

	s.testEmpty(ctx)
}

func (s *CommonStoreBackendTestSuite) TestBackupRestore() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.Run("No namespaces", func() {
		require := require.New(s.T())

		err := s.backend.Delete(ctx)
		require.NoError(err, "Failed to delete the backup")

		err = s.backend.Backup(ctx, nil)
		require.NoError(err, "Failed to backup nil map of peers")

		s.testEmpty(ctx)
	})

	s.Run("No peers", func() {
		require := require.New(s.T())

		err := s.backend.Delete(ctx)
		require.NoError(err, "Failed to delete the backup")

		err = s.backend.Backup(ctx, map[string][]peer.AddrInfo{})
		require.NoError(err, "Failed to backup empty map of peers")

		s.testEmpty(ctx)

		err = s.backend.Backup(ctx, map[string][]peer.AddrInfo{"ns-1": nil})
		require.NoError(err, "Failed to backup map with empty list of peers")

		s.testEmpty(ctx)
	})

	s.Run("No addrs", func() {
		require := require.New(s.T())

		err := s.backend.Backup(ctx, map[string][]peer.AddrInfo{
			"ns-1": {
				{
					ID:    s.addrs[0].ID,
					Addrs: []multiaddr.Multiaddr{},
				},
			},
		})
		require.NoError(err, "Failed to backup map of empty addrs")

		s.testEmpty(ctx)
	})

	s.Run("One namespace", func() {
		require := require.New(s.T())

		peers := map[string][]peer.AddrInfo{
			"ns-1": {s.addrs[0], s.addrs[1], s.addrs[2]},
		}

		err := s.backend.Backup(ctx, peers)
		require.NoError(err, "Failed to backup one namespace")

		restored, err := s.backend.Restore(ctx)
		require.NoError(err, "Failed to restore one namespace")

		require.True(reflect.DeepEqual(peers, restored), "Restored peers to not match")
	})

	s.Run("Many namespaces", func() {
		require := require.New(s.T())

		peers := map[string][]peer.AddrInfo{
			"ns-1": {s.addrs[0], s.addrs[1], s.addrs[2]},
			"ns-2": {s.addrs[2], s.addrs[3], s.addrs[4]},
			"ns-3": {s.addrs[0]},
			"ns-4": {},
		}

		err := s.backend.Backup(ctx, peers)
		require.NoError(err, "Failed to backup many namespaces")

		restored, err := s.backend.Restore(ctx)
		require.NoError(err, "Failed to restore many namespaces")

		delete(peers, "ns-4")

		require.True(reflect.DeepEqual(peers, restored), "Restored peers do not match")
	})

	s.Run("Many concurrent backups/restores", func() {
		require := require.New(s.T())

		peers := map[string][]peer.AddrInfo{
			"ns-1": {s.addrs[0], s.addrs[1], s.addrs[2]},
			"ns-2": {s.addrs[2], s.addrs[3], s.addrs[4]},
			"ns-3": {s.addrs[0]},
		}

		var wg sync.WaitGroup
		defer wg.Wait()

		n := 50
		wg.Add(n * 2)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				err := s.backend.Backup(ctx, peers)
				require.NoError(err, "Failed to backup peers")
			}()

			go func() {
				defer wg.Done()
				restored, err := s.backend.Restore(ctx)
				require.NoError(err, "Failed to restore peers")
				require.True(reflect.DeepEqual(peers, restored), "Restored peers do not match")
			}()
		}
	})
}

func (s *CommonStoreBackendTestSuite) TestNilCommonStore() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backup := NewCommonStoreBackend(nil, "bucket", "key")

	s.Run("Delete", func() {
		require := require.New(s.T())

		err := backup.Delete(ctx)
		require.NoError(err, "Failed to delete on nil common store")
	})

	s.Run("Backup", func() {
		require := require.New(s.T())

		err := backup.Backup(ctx, nil)
		require.NoError(err, "Failed to backup on nil common store")
	})

	s.Run("Restore", func() {
		require := require.New(s.T())

		_, err := backup.Restore(ctx)
		require.NoError(err, "Failed to restore on nil common store")
	})
}

func (s *CommonStoreBackendTestSuite) testEmpty(ctx context.Context) {
	require := require.New(s.T())

	peers, err := s.backend.Restore(ctx)
	require.NoError(err, "Failed to restore from empty store")
	require.Empty(peers, "There should be no peers restored from an empty store")
}
