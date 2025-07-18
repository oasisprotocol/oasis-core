package peermgmt

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/peer"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
)

const (
	// advertiseBackOffInitialInterval is the initial time interval for the exponential back-off
	// used between failed advertisements.
	advertiseBackOffInitialInterval = time.Minute

	// advertiseBackOffMaxInterval is the maximum time interval for the exponential back-off
	// used between failed advertisements.
	advertiseBackOffMaxInterval = time.Hour
)

type peerDiscovery struct {
	logger *logging.Logger

	seeds []discovery.Discovery

	mu          sync.Mutex
	advertising map[string]struct{}

	advCh chan struct{}

	startOne cmSync.One
}

func newPeerDiscovery(seeds []discovery.Discovery) *peerDiscovery {
	l := logging.GetLogger("p2p/peer-manager/discovery")

	return &peerDiscovery{
		logger:      l,
		seeds:       seeds,
		advertising: make(map[string]struct{}),
		advCh:       make(chan struct{}, 1),
		startOne:    cmSync.NewOne(),
	}
}

// start starts advertising services to seed nodes.
func (d *peerDiscovery) start() {
	d.startOne.TryStart(d.run)
}

// stop stops advertising services to seed nodes.
func (d *peerDiscovery) stop() {
	d.startOne.TryStop()
}

// findPeers tries to discover peers for the given namespace.
func (d *peerDiscovery) findPeers(ctx context.Context, ns string) <-chan peer.AddrInfo {
	// Select seeds at random until one responds.
	for _, pos := range rand.Perm(len(d.seeds)) {
		peerCh, err := d.seeds[pos].FindPeers(ctx, ns)
		if err != nil {
			d.logger.Error("failed to find peers",
				"err", err,
				"namespace", ns,
			)
			if ctx.Err() != nil {
				break
			}
			continue
		}

		return peerCh
	}

	// If no one responds, just return a closed channel.
	peerCh := make(chan peer.AddrInfo)
	close(peerCh)

	return peerCh
}

// startAdvertising starts advertising the given namespace. Advertisements are done only when
// the discovery is running.
func (d *peerDiscovery) startAdvertising(ns string) {
	if len(d.seeds) == 0 {
		return
	}

	d.mu.Lock()
	d.advertising[ns] = struct{}{}
	d.mu.Unlock()

	select {
	case d.advCh <- struct{}{}:
	default:
	}

	d.logger.Debug("triggered protocol advertisement",
		"protocol", ns,
	)
}

// stopAdvertising stops advertising the given namespace.
func (d *peerDiscovery) stopAdvertising(ns string) {
	if len(d.seeds) == 0 {
		return
	}

	d.mu.Lock()
	delete(d.advertising, ns)
	d.mu.Unlock()

	select {
	case d.advCh <- struct{}{}:
	default:
	}
}

func (d *peerDiscovery) run(ctx context.Context) {
	if len(d.seeds) == 0 {
		return
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	// Force advertise check at startup.
	select {
	case d.advCh <- struct{}{}:
	default:
	}

	// Handle advertise start/stop requests.
	ongoing := make(map[string]context.CancelFunc)

	for {
		select {
		case <-d.advCh:
		case <-ctx.Done():
			return
		}

		// Something has changed. Check which namespaces where added or removed.
		func() {
			d.mu.Lock()
			defer d.mu.Unlock()

			// Stop advertising removed ones.
			for ns, cancel := range ongoing {
				if _, ok := d.advertising[ns]; ok {
					continue
				}

				delete(ongoing, ns)
				cancel()

				d.logger.Info("stopped advertising",
					"namespace", ns,
				)
			}

			// Start advertising added ones.
			for ns := range d.advertising {
				if _, ok := ongoing[ns]; ok {
					continue
				}

				advCtx, advCancel := context.WithCancel(ctx)
				ongoing[ns] = advCancel

				wg.Add(len(d.seeds))
				for _, seed := range d.seeds {
					go func(seed discovery.Discovery, ns string) {
						defer wg.Done()
						d.advertise(advCtx, seed, ns)
					}(seed, ns)
				}

				d.logger.Info("started advertising",
					"namespace", ns,
				)
			}
		}()
	}
}

func (d *peerDiscovery) advertise(ctx context.Context, seed discovery.Advertiser, namespace string) {
	bo := cmnBackoff.NewExponentialBackOff()
	bo.InitialInterval = advertiseBackOffInitialInterval
	bo.MaxInterval = advertiseBackOffMaxInterval
	bo.Reset()

	for {
		ttl, err := seed.Advertise(ctx, namespace)
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			d.logger.Debug("failed to advertise",
				"err", err,
				"namespace", namespace,
			)

			// Retry if failed.
			select {
			case <-time.After(bo.NextBackOff()):
				continue
			case <-ctx.Done():
				return
			}
		}

		// Advertise before the deadline.
		select {
		case <-time.After(ttl * 7 / 8):
		case <-ctx.Done():
			return
		}

		bo.Reset()
	}
}
