package peerstore

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/oasisprotocol/oasis-core/go/p2p/backup"
)

type StoreTestSuite struct {
	suite.Suite

	store *Store
	infos []peer.AddrInfo
}

func (s *StoreTestSuite) SetupSuite() {
	require := require.New(s.T())

	s.infos = make([]peer.AddrInfo, 5)
	for i := 0; i < len(s.infos); i++ {
		_, pk, err := crypto.GenerateKeyPair(crypto.Ed25519, 0)
		require.NoError(err)

		id, err := peer.IDFromPublicKey(pk)
		require.NoError(err)

		s.infos[i] = peer.AddrInfo{
			ID:    id,
			Addrs: make([]multiaddr.Multiaddr, 0),
		}
	}
}

func (s *StoreTestSuite) SetupTest() {
	require := require.New(s.T())

	// Prepare store with few entries.
	s.store = NewStore(backup.NewInMemoryBackend())

	_, err := s.store.Add("ns-1", s.infos[0])
	require.NoError(err)
	_, err = s.store.Add("ns-1", s.infos[1])
	require.NoError(err)
	_, err = s.store.Add("ns-1", s.infos[2])
	require.NoError(err)

	_, err = s.store.Add("ns-2", s.infos[0])
	require.NoError(err)
	_, err = s.store.Add("ns-2", s.infos[3])
	require.NoError(err)
}

func (s *StoreTestSuite) TestNewStore() {
	require := require.New(s.T())

	store := NewStore(backup.NewInMemoryBackend())
	require.NotNil(store.logger, "logger should be initialized")
	require.NotNil(store.registrations, "registrations should be initialized")
	require.NotNil(store.expirations, "expirations should be initialized")
}

func (s *StoreTestSuite) TestAdd() {
	require := require.New(s.T())

	// Happy path.
	require.Equal(3, s.store.size("ns-1"))
	require.Equal(2, s.store.size("ns-2"))
	require.Equal(5, s.store.total())

	// Add few existing.
	_, err := s.store.Add("ns-1", s.infos[0])
	require.NoError(err)
	_, err = s.store.Add("ns-1", s.infos[1])
	require.NoError(err)

	// Numbers should not change.
	require.Equal(3, s.store.size("ns-1"))
	require.Equal(2, s.store.size("ns-2"))
	require.Equal(5, s.store.total())
}

func (s *StoreTestSuite) TestRemove() {
	require := require.New(s.T())

	// Remove few.
	s.store.Remove("ns-1", s.infos[0].ID)
	s.store.Remove("ns-2", s.infos[3].ID)

	// Remove non-existing.
	s.store.Remove("ns-1", s.infos[4].ID)
	s.store.Remove("ns-404", s.infos[0].ID)
	s.store.Remove("ns-404", s.infos[4].ID)

	require.Equal(2, s.store.size("ns-1"))
	require.Equal(1, s.store.size("ns-2"))
	require.Equal(3, s.store.total())
}

func (s *StoreTestSuite) TestNamespacePeers() {
	require := require.New(s.T())

	require.Equal(3, s.store.size("ns-1"))
	require.Equal(2, s.store.size("ns-2"))

	// Non-existing namespace.
	peers := s.store.NamespacePeers("ns-404", 10)
	require.Empty(peers)

	// Happy path.
	peers = s.store.NamespacePeers("ns-1", 10)
	require.Len(peers, 3)

	// With limit.
	peers = s.store.NamespacePeers("ns-2", 1)
	require.Len(peers, 1)
}

func (s *StoreTestSuite) TestPeers() {
	require := require.New(s.T())

	// Happy path.
	peers := s.store.Peers()
	require.Len(peers, 4)
}

func (s *StoreTestSuite) TestStoreOptions() {
	require := require.New(s.T())

	s.Run("Max peers", func() {
		store := NewStore(backup.NewInMemoryBackend(),
			WithMaxPeers(2),
		)

		// Add two peers.
		_, err := store.Add("ns-1", s.infos[0])
		require.NoError(err)
		_, err = store.Add("ns-2", s.infos[1])
		require.NoError(err)

		// Third addition should fail.
		_, err = store.Add("ns-3", s.infos[2])
		require.Error(err)

		// But if we remove one we can add another one.
		store.Remove("ns-2", s.infos[1].ID)
		_, err = store.Add("ns-3", s.infos[2])
		require.NoError(err)
	})

	s.Run("Max namespace peers", func() {
		store := NewStore(backup.NewInMemoryBackend(),
			WithMaxNamespacePeers(1),
		)

		// Add one twice.
		_, err := store.Add("ns-1", s.infos[0])
		require.NoError(err)
		_, err = store.Add("ns-1", s.infos[0])
		require.NoError(err)

		// Add a second one and reach max number of peers in namespace ns-1.
		_, err = store.Add("ns-1", s.infos[1])
		require.Error(err)

		// Remove one and test if we can add again.
		store.Remove("ns-1", s.infos[0].ID)
		_, err = store.Add("ns-1", s.infos[1])
		require.NoError(err)
	})

	s.Run("Max peer's namespaces", func() {
		store := NewStore(backup.NewInMemoryBackend(),
			WithMaxPeerNamespaces(1),
		)

		_, err := store.Add("ns-1", s.infos[0])
		require.NoError(err)
		_, err = store.Add("ns-2", s.infos[0])
		require.Error(err)
	})
}

func (s *StoreTestSuite) TestBackupRestore() {
	require := require.New(s.T())

	// Backup and restore to a different store.
	err := s.store.Backup(context.Background())
	require.NoError(err)

	store := NewStore(s.store.backup)
	err = store.Restore(context.Background())
	require.NoError(err)

	// Numbers should not change.
	require.Equal(3, store.size("ns-1"))
	require.Equal(2, store.size("ns-2"))
	require.Equal(5, store.total())
}

func (s *StoreTestSuite) TestStartStop() {
	s.store.Start()
	s.store.Stop()
}

func (s *StoreTestSuite) TestClean() {
	require := require.New(s.T())

	require.Equal(3, s.store.size("ns-1"))
	require.Equal(2, s.store.size("ns-2"))
	require.Equal(5, s.store.expirations.Len())

	// Fake expirations of the first two in line.
	s.store.registrations["ns-1"][s.infos[0].ID].expires = time.Now()
	s.store.registrations["ns-1"][s.infos[1].ID].expires = time.Now()

	err := s.store.cleanup(context.Background())
	require.NoError(err)

	require.Equal(1, s.store.size("ns-1"))
	require.Equal(2, s.store.size("ns-2"))
	require.Equal(3, s.store.expirations.Len())
}

func TestStoreTestSuite(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}
