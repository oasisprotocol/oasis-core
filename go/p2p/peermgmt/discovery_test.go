package peermgmt

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type DiscoveryTestSuite struct {
	suite.Suite

	mu               sync.Mutex
	discoveryCounter int
	advertiseCounter int

	discovery *peerDiscovery
}

func TestDiscoveryTestSuite(t *testing.T) {
	suite.Run(t, new(DiscoveryTestSuite))
}

func (s *DiscoveryTestSuite) SetupSuite() {
	numSeeds := 3
	seeds := make([]discovery.Discovery, 0, numSeeds)
	for i := 0; i < numSeeds; i++ {
		seeds = append(seeds, s)
	}

	s.discovery = newPeerDiscovery(seeds)
}

func (s *DiscoveryTestSuite) TestStartStop() {
	for i := 0; i < 5; i++ {
		s.discovery.start()
		s.discovery.stop()
	}
}

func (s *DiscoveryTestSuite) TestFindPeers() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	s.Run("Happy path", func() {
		require := require.New(s.T())

		peers := s.discovery.findPeers(ctx, "ns-1")
		require.Equal(3, len(peers))
		require.Equal(1, s.discoveryCount())
	})

	s.Run("Errors", func() {
		require := require.New(s.T())

		// Should try all seeds.
		peers := s.discovery.findPeers(ctx, "ns-0")
		require.Equal(0, len(peers))
		require.Equal(4, s.discoveryCount())
	})
}

func (s *DiscoveryTestSuite) TestAdvertise() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	checkAdvertiseCounter := func(t *testing.T, expected int) {
		for {
			select {
			case <-time.After(time.Microsecond):
				if expected == s.advertiseCount() {
					return
				}
			case <-ctx.Done():
				require.Equal(t, expected, s.advertiseCount())
				return
			}
		}
	}

	s.Run("Not running", func() {
		s.discovery.startAdvertising("ns-1")
		s.discovery.startAdvertising("ns-1")
		s.discovery.startAdvertising("ns-2")

		time.Sleep(10 * time.Millisecond)

		checkAdvertiseCounter(s.T(), 0)
	})

	s.discovery.start()

	s.Run("Startup", func() {
		checkAdvertiseCounter(s.T(), 6)
	})

	s.Run("Running", func() {
		s.discovery.startAdvertising("ns-1")
		s.discovery.startAdvertising("ns-2")
		s.discovery.startAdvertising("ns-3")

		time.Sleep(10 * time.Millisecond)

		checkAdvertiseCounter(s.T(), 9)
	})

	s.Run("Error", func() {
		s.discovery.startAdvertising("ns-0")

		time.Sleep(10 * time.Millisecond)

		checkAdvertiseCounter(s.T(), 9)
	})

	s.discovery.stop()
	s.discovery.start()

	s.Run("Restart", func() {
		checkAdvertiseCounter(s.T(), 18)
	})

	s.discovery.stop()
}

func (s *DiscoveryTestSuite) advertiseCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.advertiseCounter
}

func (s *DiscoveryTestSuite) discoveryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discoveryCounter
}

func (s *DiscoveryTestSuite) FindPeers(_ context.Context, ns string, _ ...discovery.Option) (<-chan peer.AddrInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.discoveryCounter++

	if ns == "ns-0" {
		return nil, fmt.Errorf("broken seed")
	}

	ch := make(chan peer.AddrInfo, 3)
	for i := 0; i < 3; i++ {
		ch <- peer.AddrInfo{}
	}
	close(ch)

	return ch, nil
}

func (s *DiscoveryTestSuite) Advertise(_ context.Context, ns string, _ ...discovery.Option) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ns == "ns-0" {
		return 0, fmt.Errorf("broken seed")
	}

	s.advertiseCounter++

	return time.Hour, nil
}
