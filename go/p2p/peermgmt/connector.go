package peermgmt

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

const (
	// connectBackOffInitialInterval is the initial time interval for the exponential back-off
	// used between failed connection attempts.
	connectBackOffInitialInterval = time.Minute

	// connectBackOffMaxInterval is the maximum time interval for the exponential back-off
	// used between failed connection attempts.
	connectBackOffMaxInterval = 4 * time.Hour
)

type peerConn struct {
	connected bool
	doneCh    chan struct{}
}

type peerConnector struct {
	logger *logging.Logger

	host  host.Host
	gater connmgr.ConnectionGater

	mu       sync.Mutex
	ongoing  map[core.PeerID]*peerConn
	backoffs map[core.PeerID]*backOff
}

func newPeerConnector(h host.Host, g connmgr.ConnectionGater) *peerConnector {
	l := logging.GetLogger("p2p/peer-manager/connector")

	return &peerConnector{
		logger:   l,
		host:     h,
		gater:    g,
		ongoing:  make(map[core.PeerID]*peerConn),
		backoffs: make(map[core.PeerID]*backOff),
	}
}

// connectMany tries to connect to the given peers until max number of peers are connected.
// Already connected peers count as if a connection was successfully established.
//
// Note that at the end more than max number of peers from the given list can be connected as some
// of them might already be connected prior the method call or connected via some other means.
func (c *peerConnector) connectMany(ctx context.Context, peersCh <-chan peer.AddrInfo, max int) {
	if max <= 0 {
		return
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	// Try connecting to peers in parallel until enough connections are established.
	// Note that connections are throttled inside libp2p package.
	ticketCh := make(chan bool, max)
	for i := 0; i < max; i++ {
		ticketCh <- false
	}

	var (
		ok        bool
		connected bool
		info      peer.AddrInfo
	)

	for {
		select {
		case info, ok = <-peersCh:
		case <-ctx.Done():
			return
		}

		if !ok {
			return
		}

		for {
			// Wait for a ticket/failed connection.
			select {
			case connected = <-ticketCh:
			case <-ctx.Done():
				return
			}

			// We got a ticket. Connect to the next peer if the peer holding it failed to connect.
			// Otherwise wait for another one unless there are no more tickets available.
			if !connected {
				break
			}

			max--
			if max == 0 {
				return
			}
		}

		// Connect in the background.
		wg.Add(1)
		go func(info peer.AddrInfo) {
			defer wg.Done()
			ticketCh <- c.connectOne(ctx, info)
		}(info)
	}
}

// connectOne tries to connect to the given peer allowing only one connection attempt at a time.
func (c *peerConnector) connectOne(ctx context.Context, info peer.AddrInfo) bool {
	// Allow only one connection at a time.
	c.mu.Lock()
	req, ok := c.ongoing[info.ID]
	if !ok {
		req = &peerConn{
			doneCh: make(chan struct{}),
		}
		c.ongoing[info.ID] = req
	}
	c.mu.Unlock()

	// If we are already trying to connect to the peer, wait for the result.
	// No need for mutex as reads are done after the channel closes.
	if ok {
		<-req.doneCh
		return req.connected
	}

	req.connected = c.connect(ctx, info)

	// Mark connection request as finished.
	c.mu.Lock()
	delete(c.ongoing, info.ID)
	c.mu.Unlock()

	close(req.doneCh)

	return req.connected
}

// connect tries to connect to the given peer.
func (c *peerConnector) connect(ctx context.Context, info peer.AddrInfo) bool {
	if info.ID == c.host.ID() {
		return false
	}

	// Don't bother doing anything if the address list is empty.
	// It's unlikely for connection attempts to no addresses to succeed.
	if len(info.Addrs) == 0 {
		c.logger.Debug("no addresses to connect to",
			"peer_id", info.ID,
		)
		return false
	}

	// Skip blocked peer before even trying to dial.
	if !c.gater.InterceptPeerDial(info.ID) {
		return false
	}

	// Skip if the peer is connected.
	if c.host.Network().Connectedness(info.ID) == network.Connected {
		return true
	}

	if !c.checkBackOff(info.ID) {
		return false
	}

	c.logger.Debug("trying to connect to peer",
		"peer_id", info.ID,
		"peer_addrs", info.Addrs,
	)

	// Finally, connect. No need to add timeout to the context as this is
	// already done in the libp2p package.
	if err := c.host.Connect(ctx, info); err != nil {
		c.logger.Debug("failed to connect to peer",
			"err", err,
			"peer_id", info.ID,
			"peer_addrs", info.Addrs,
		)

		if !errors.Is(err, context.Canceled) {
			c.extendBackOff(info.ID)
		}

		return false
	}

	c.resetBackOff(info.ID)

	return true
}

func (c *peerConnector) checkBackOff(p core.PeerID) bool {
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	bo, ok := c.backoffs[p]
	if !ok {
		bo = newBackOff(now, connectBackOffInitialInterval, connectBackOffMaxInterval)
		c.backoffs[p] = bo
	}

	return bo.check(now)
}

func (c *peerConnector) extendBackOff(p core.PeerID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.backoffs[p].extend()
}

func (c *peerConnector) resetBackOff(p core.PeerID) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.backoffs[p].reset()
}
