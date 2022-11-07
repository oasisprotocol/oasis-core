package peermgmt

import (
	"context"
	"io/ioutil"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/oasisprotocol/oasis-core/go/common/persistent"
)

type BackupTestSuite struct {
	suite.Suite

	dir   string
	store *persistent.CommonStore

	host  host.Host
	peers []host.Host
	infos []*peer.AddrInfo

	backup *peerstoreBackup
}

func TestBackupTestSuite(t *testing.T) {
	suite.Run(t, new(BackupTestSuite))
}

func (s *BackupTestSuite) SetupSuite() {
	require := require.New(s.T())

	var err error
	s.dir, err = ioutil.TempDir("", "oasis-p2p-backup-test_")
	require.NoError(err, "TempDir failed")

	s.store, err = persistent.NewCommonStore(s.dir)
	require.NoError(err, "NewCommonStore failed")

	// One host.
	s.host, err = newTestHost()
	require.NoError(err, "newTestHost failed")

	// Few peers.
	n := 10
	s.peers = make([]host.Host, 0, n)
	for i := 0; i < n; i++ {
		host, err := newTestHost()
		require.NoError(err, "newTestHost failed")

		s.peers = append(s.peers, host)
	}

	s.infos = make([]*peer.AddrInfo, 0, len(s.peers))
	for _, p := range s.peers {
		info := peer.AddrInfo{
			ID:    p.ID(),
			Addrs: p.Addrs(),
		}
		s.infos = append(s.infos, &info)
	}

	// One backup to play with.
	s.backup = newPeerstoreBackup(s.host, s.store)
}

func (s *BackupTestSuite) TearDownSuite() {
	require := require.New(s.T())

	for _, p := range s.peers {
		err := p.Close()
		require.NoError(err, "Peer Close failed")
	}

	err := s.host.Close()
	require.NoError(err, "Host Close failed")

	if s.dir != "" {
		os.RemoveAll(s.dir)
	}
}

func (s *BackupTestSuite) TestStoreLoad() {
	require := require.New(s.T())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.Run("Empty store", func() {
		// Make sure no one is connected.
		require.Equal(0, len(s.host.Network().Peers()))

		// Clear store.
		db, err := s.store.GetServiceStore(storeBucketName)
		require.NoError(err, "GetServiceStore failed")

		err = db.Delete([]byte(storePeerstoreKey))
		require.NoError(err, "Delete failed")

		// Store empty peerstore.
		err = s.backup.save()
		require.NoError(err, "Store failed on empty peerstore")

		// Load empty db.
		_, err = s.backup.load()
		require.Error(err, "Load should fail on empty db")
	})

	s.Run("One peer", func() {
		// Connect one peer.
		err := s.host.Connect(ctx, *s.infos[0])
		require.NoError(err, "Connect failed")

		// Store peerstore with one peer.
		err = s.backup.save()
		require.NoError(err, "Store failed")

		// Load db.
		peers, err := s.backup.load()
		require.NoError(err, "Load failed")
		require.Len(peers, 1)
	})

	s.Run("Many peers", func() {
		// Connect many peers.
		for _, info := range s.infos {
			err := s.host.Connect(ctx, *info)
			require.NoError(err, "Connect failed")
		}

		// Store peerstore with many peers.
		err := s.backup.save()
		require.NoError(err, "Store failed")

		// Load db.
		peers, err := s.backup.load()
		require.NoError(err, "Load failed")
		require.Len(peers, len(s.infos))
	})

	s.Run("Concurrency", func() {
		// Many concurrent loads/saves.
		var wg sync.WaitGroup
		defer wg.Wait()

		n := 10
		wg.Add(n * 2)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				err := s.backup.save()
				require.NoError(err, "Store failed")
			}()

			go func() {
				defer wg.Done()
				peers, err := s.backup.load()
				require.NoError(err, "Load failed")
				require.Len(peers, len(s.infos))
			}()
		}
	})
}

func (s *BackupTestSuite) TestStartStop() {
	s.Run("Backup stops", func() {
		s.backup.start()
		s.backup.stop()
	})

	s.Run("Backups stop", func() {
		var wg sync.WaitGroup
		defer wg.Wait()

		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.backup.start()
				s.backup.stop()
			}()
		}
	})
}

func (s *BackupTestSuite) TestRestore() {
	require := require.New(s.T())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.Run("Happy path", func() {
		// Connect all peers.
		for _, info := range s.infos {
			err := s.host.Connect(ctx, *info)
			require.NoError(err, "Connect failed")
		}

		// Store peerstore with one peer.
		err := s.backup.save()
		require.NoError(err, "Store failed")

		// Disconnect all peers.
		for _, info := range s.infos {
			err = s.host.Network().ClosePeer(info.ID)
			require.NoError(err, "ClosePeer failed")
		}
		require.Equal(0, len(s.host.Network().Peers()))

		// Do restore and check if everyone is connected.
		gater, err := conngater.NewBasicConnectionGater(nil)
		require.NoError(err, "NewBasicConnectionGater failed")
		connector := newPeerConnector(s.host, gater)
		s.backup.restore(ctx, connector)

		require.Equal(len(s.infos), len(s.host.Network().Peers()))

		// Reset.
		for _, info := range s.infos {
			err := s.host.Network().ClosePeer(info.ID)
			require.NoError(err, "ClosePeer failed")
		}
		require.Equal(0, len(s.host.Network().Peers()))
	})
}
