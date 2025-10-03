package peermgmt

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoremem"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/oasisprotocol/oasis-core/go/p2p/backup"
)

type PeerstoreBackupTestSuite struct {
	suite.Suite

	store   peerstore.Peerstore
	backup  *peerstoreBackup
	backend backup.Backend

	infos []peer.AddrInfo
}

func TestPeerstoreBackupTestSuite(t *testing.T) {
	suite.Run(t, new(PeerstoreBackupTestSuite))
}

func (s *PeerstoreBackupTestSuite) SetupSuite() {
	require := require.New(s.T())

	s.infos = make([]peer.AddrInfo, 5)
	for i := 0; i < len(s.infos); i++ {
		_, pk, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
		require.NoError(err, "GenerateKeyPair failed")

		id, err := peer.IDFromPublicKey(pk)
		require.NoError(err, "IDFromPublicKey failed")

		addr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d/", 8000+i))
		require.NoError(err, "NewMultiaddr failed")

		s.infos[i] = peer.AddrInfo{
			ID:    id,
			Addrs: []multiaddr.Multiaddr{addr},
		}
	}

	var err error
	s.store, err = pstoremem.NewPeerstore()
	require.NoError(err, "NewPeerstore failed")

	s.backend = backup.NewInMemoryBackend()
	s.backup = newPeerstoreBackup(s.store, s.backend)
}

func (s *PeerstoreBackupTestSuite) TestBackupRestore() {
	clearStore := func(t *testing.T) {
		for _, p := range s.store.Peers() {
			s.store.ClearAddrs(p)
		}
		require.Empty(t, s.store.PeersWithAddrs())
	}

	s.Run("Empty store", func() {
		require := require.New(s.T())

		// Ensure that the store is empty.
		clearStore(s.T())

		// Store empty peerstore.
		err := s.backup.backup(context.Background())
		require.NoError(err, "Backup failed on empty peerstore")

		// Load empty db.
		err = s.backup.restore(context.Background())
		require.NoError(err, "Restore failed on empty db")
		require.Empty(s.store.PeersWithAddrs())
	})

	s.Run("One peer", func() {
		require := require.New(s.T())

		// Add one peer.
		s.store.AddAddrs(s.infos[0].ID, s.infos[0].Addrs, peerstore.RecentlyConnectedAddrTTL)

		// Store peerstore with one peer.
		err := s.backup.backup(context.Background())
		require.NoError(err, "Backup failed")

		// Ensure that the store is empty.
		clearStore(s.T())

		// Load one peer.
		err = s.backup.restore(context.Background())
		require.NoError(err, "Restore failed")
		require.Len(s.store.PeersWithAddrs(), 1)
	})

	s.Run("Many peers", func() {
		require := require.New(s.T())

		// Add many peers.
		for _, info := range s.infos {
			s.store.AddAddrs(info.ID, info.Addrs, peerstore.RecentlyConnectedAddrTTL)
		}

		// Store peerstore with one peer.
		err := s.backup.backup(context.Background())
		require.NoError(err, "Backup failed")

		// Ensure that the store is empty.
		clearStore(s.T())

		// Load one peer.
		err = s.backup.restore(context.Background())
		require.NoError(err, "Restore failed")
		require.Len(s.store.PeersWithAddrs(), len(s.infos))
	})

	s.Run("Many concurrent backups/restores", func() {
		require := require.New(s.T())

		// Many concurrent loads/saves.
		var wg sync.WaitGroup
		defer wg.Wait()

		n := 50
		wg.Add(n * 2)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				err := s.backup.backup(context.Background())
				require.NoError(err, "Backup failed")
			}()

			go func() {
				defer wg.Done()
				err := s.backup.restore(context.Background())
				require.NoError(err, "Restore failed")
			}()
		}
	})
}

func (s *PeerstoreBackupTestSuite) TestStartStop() {
	s.Run("Backup stops", func() {
		s.backup.start()
		s.backup.stop()
	})

	s.Run("Backups stop", func() {
		var wg sync.WaitGroup
		defer wg.Wait()

		for range 100 {
			wg.Go(func() {
				s.backup.start()
				s.backup.stop()
			})
		}
	})
}
