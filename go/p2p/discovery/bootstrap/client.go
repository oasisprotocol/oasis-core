package bootstrap

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// defaultRetentionPeriod is the default peer retention period.
	defaultRetentionPeriod = time.Hour

	// discoveryBackOffInitialInterval is the initial time interval for the exponential back-off
	// used between failed discoveries.
	discoveryBackOffInitialInterval = time.Minute

	// discoveryBackOffMaxInterval is the maximum time interval for the exponential back-off
	// used between failed discoveries.
	discoveryBackOffMaxInterval = time.Hour

	// maliciousSeedBackOff is the time interval during which no peers will be returned if the seed
	// has behaved maliciously.
	maliciousSeedBackOff = 24 * time.Hour
)

// ClientOptions are client's peer discovery options.
type ClientOptions struct {
	retentionPeriod time.Duration
}

// ClientOption is a client peer discovery option setter.
type ClientOption func(opts *ClientOptions)

// WithRetentionPeriod configures peer retention period.
func WithRetentionPeriod(retentionPeriod time.Duration) ClientOption {
	return func(opts *ClientOptions) {
		opts.retentionPeriod = retentionPeriod
	}
}

// DefaultClientOptions returns the default client options.
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		retentionPeriod: defaultRetentionPeriod,
	}
}

type discoveryCache struct {
	peers   []peer.AddrInfo
	expires time.Time
	limit   int
}

// client is an implementation of a peer discovery that fetches peers from the seed node and
// advertises services.
type client struct {
	logger *logging.Logger

	host host.Host
	rc   rpc.Client

	seed            peer.AddrInfo
	retentionPeriod time.Duration

	mu            sync.Mutex
	nextDiscovery time.Time
	backoff       *backoff.ExponentialBackOff
	cache         map[string]*discoveryCache
}

// NewClient creates a new bootstrap protocol client.
func NewClient(h host.Host, seed peer.AddrInfo, opts ...ClientOption) discovery.Discovery {
	l := logging.GetLogger("p2p/discovery/bootstrap").With(
		"seed_id", seed.ID,
		"seed_addrs", seed.Addrs,
	)

	cos := DefaultClientOptions()
	for _, opt := range opts {
		opt(cos)
	}

	// Add the seed to the peer store so that libp2p knows how to contact it.
	h.Peerstore().AddAddrs(seed.ID, seed.Addrs, peerstore.PermanentAddrTTL)

	rc := rpc.NewClient(h, ProtocolID())

	bo := cmnBackoff.NewExponentialBackOff()
	bo.InitialInterval = discoveryBackOffInitialInterval
	bo.MaxInterval = discoveryBackOffMaxInterval
	bo.Reset()

	return &client{
		logger:          l,
		host:            h,
		rc:              rc,
		seed:            seed,
		retentionPeriod: cos.retentionPeriod,
		nextDiscovery:   time.Now(),
		backoff:         bo,
		cache:           make(map[string]*discoveryCache),
	}
}

// Advertise implements discovery.Advertiser and discovery.Discovery.
func (c *client) Advertise(ctx context.Context, ns string, _ ...discovery.Option) (time.Duration, error) {
	req := AdvertiseRequest{
		Namespace: ns,
	}
	var res AdvertiseResponse

	pf, err := c.rc.Call(ctx, c.seed.ID, MethodAdvertise, req, &res)
	if err != nil {
		pf.RecordFailure()

		c.logger.Error("failed to advertise",
			"err", err,
		)
		return 0, fmt.Errorf("failed to advertise: %w", err)
	}

	pf.RecordSuccess()

	// Try to close connections after every call because requests to the seed node are infrequent.
	if err = c.rc.CloseIdle(c.seed.ID); err != nil {
		c.logger.Warn("failed to close idle connections to seed node",
			"err", err,
		)
	}

	return res.TTL, nil
}

// FindPeers implements discovery.Discoverer and discovery.Discovery.
func (c *client) FindPeers(ctx context.Context, ns string, opts ...discovery.Option) (<-chan peer.AddrInfo, error) {
	// Check how many peers we need to fetch.
	var options discovery.Options
	err := options.Apply(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to apply options: %w", err)
	}
	limit := options.Limit

	// Fetch peers and flush them down the channel.
	ch := make(chan peer.AddrInfo)
	go func() {
		defer close(ch)
		peers := c.fetchPeers(ctx, ns, limit)
		sendPeers(ctx, ch, peers, limit)
	}()

	return ch, nil
}

func (c *client) fetchPeers(ctx context.Context, ns string, limit int) []peer.AddrInfo {
	// Allow only one fetch request at a time. No need for parallelism here as speed is not
	// crucial and the number of requests should be low anyway.
	c.mu.Lock()
	defer c.mu.Unlock()

	cache, ok := c.cache[ns]
	if !ok {
		cache = &discoveryCache{}
		c.cache[ns] = cache
	}

	now := time.Now()
	if c.nextDiscovery.After(now) {
		return cache.peers
	}
	if cache.expires.After(now) && (cache.limit == 0 || cache.limit >= limit && limit != 0) {
		return cache.peers
	}

	peers, pf, err := func() ([]peer.AddrInfo, rpc.PeerFeedback, error) {
		req := DiscoverRequest{
			Namespace: ns,
			Limit:     limit,
		}
		var rsp DiscoverResponse

		pf, err := c.rc.Call(ctx, c.seed.ID, MethodDiscover, req, &rsp)
		if err != nil {
			c.logger.Error("failed to call seed node",
				"err", err,
			)
			return nil, pf, err
		}

		if limit != 0 && len(rsp.Peers) > limit {
			c.logger.Debug("seed node returned too many peers",
				"limit", limit,
				"received", len(rsp.Peers),
			)
			return nil, pf, ErrMaliciousSeed
		}

		peers := make([]peer.AddrInfo, len(rsp.Peers))
		for i, json := range rsp.Peers {
			err := peers[i].UnmarshalJSON(json)
			if err != nil {
				c.logger.Debug("failed to unmarshal addr info",
					"err", err,
				)
				return nil, pf, ErrMaliciousSeed
			}
		}

		return peers, pf, nil
	}()

	switch err {
	case nil:
		// All good. Start serving new peers.
		cache.peers = peers
		cache.limit = limit
		cache.expires = now.Add(c.retentionPeriod)

		c.backoff.Reset()
		pf.RecordSuccess()

	case ErrMaliciousSeed:
		// Return no peers while the seed is marked as malicious.
		cache.peers = nil
		cache.limit = 0
		cache.expires = now.Add(maliciousSeedBackOff)

		pf.RecordFailure()
		pf.RecordBadPeer()
	default:
		// Keep serving peers from the cache if something went wrong.
		c.nextDiscovery = now.Add(c.backoff.NextBackOff())

		pf.RecordFailure()
	}

	// Try to close connections after every call because requests to the seed node are infrequent.
	if err = c.rc.CloseIdle(c.seed.ID); err != nil {
		c.logger.Warn("failed to close idle connections to seed node",
			"err", err,
		)
	}

	return cache.peers
}

func sendPeers(ctx context.Context, peerCh chan<- peer.AddrInfo, peers []peer.AddrInfo, limit int) {
	if limit == 0 || limit > len(peers) {
		limit = len(peers)
	}

	order := rand.Perm(len(peers))[:limit]
	for _, i := range order {
		select {
		case peerCh <- peers[i]:
		case <-ctx.Done():
			return
		}
	}
}
