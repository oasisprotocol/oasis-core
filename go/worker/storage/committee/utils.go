package committee

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
)

// outstandingMask records which storage roots still need to be synced or need to be retried.
// It is a bitwise set of storageApi.RootType values.
type outstandingMask uint

func bitForType(rootType storageApi.RootType) outstandingMask {
	return outstandingMask(1 << (int(rootType) - 1))
}

var outstandingMaskFull = bitForType(storageApi.RootTypeMax+1) - 1

func (o outstandingMask) String() string {
	represented := make([]string, 0, storageApi.RootTypeMax)
	for i := storageApi.RootType(1); i <= storageApi.RootTypeMax; i++ {
		if (1<<bitForType(i))&o != 0 {
			represented = append(represented, i.String())
		}
	}
	return fmt.Sprintf("outstanding_mask{%s}", strings.Join(represented, ", "))
}

func (o *outstandingMask) add(rootType storageApi.RootType) {
	*o = (*o) | bitForType(rootType)
}

func (o *outstandingMask) remove(rootType storageApi.RootType) {
	*o = (*o) & ^bitForType(rootType)
}

func (o outstandingMask) contains(rootType storageApi.RootType) bool {
	return o&bitForType(rootType) > 0
}

func (o outstandingMask) isEmpty() bool {
	return o == 0
}

func (o outstandingMask) hasAll() bool {
	return o == outstandingMaskFull
}

type inFlight struct {
	startedAt     time.Time
	outstanding   outstandingMask
	awaitingRetry outstandingMask
}

func (i *inFlight) scheduleDiff(rootType storageApi.RootType) {
	i.outstanding.add(rootType)
	i.awaitingRetry.remove(rootType)
}

func (i *inFlight) retry(rootType storageApi.RootType) {
	i.outstanding.remove(rootType)
	i.awaitingRetry.add(rootType)
}

// blockSummary is a short summary of a single block.Block.
type blockSummary struct {
	Namespace common.Namespace  `json:"namespace"`
	Round     uint64            `json:"round"`
	Roots     []storageApi.Root `json:"roots"`
}

func (s *blockSummary) GetRound() uint64 {
	return s.Round
}

func summaryFromBlock(blk *block.Block) *blockSummary {
	return &blockSummary{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
		Roots:     blk.Header.StorageRoots(),
	}
}

type heartbeat struct {
	*backoff.Ticker
}

func (h *heartbeat) reset() {
	if h.Ticker != nil {
		h.Stop()
	}

	boff := cmnBackoff.NewExponentialBackOff()
	boff.InitialInterval = 5 * time.Second
	boff.MaxInterval = 20 * time.Second
	h.Ticker = backoff.NewTicker(boff)

	// Gobble the first tick, which is immediate.
	<-h.C
}

type expBackoff struct {
	lock sync.Mutex

	backoff *backoff.ExponentialBackOff
	t       time.Duration
}

func newBackoff(minTimeout time.Duration, maxTimeout time.Duration) *expBackoff {
	// Backoff configuration for syncing failures.
	backoff := cmnBackoff.NewExponentialBackOff()
	backoff.InitialInterval = minTimeout
	backoff.MaxInterval = maxTimeout
	backoff.Reset()

	return &expBackoff{
		backoff: backoff,
	}
}

func (b *expBackoff) success() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.backoff.Reset()
	b.t = 0
}

func (b *expBackoff) failure() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.t = b.backoff.NextBackOff()
}

func (b *expBackoff) timeout() time.Duration {
	b.lock.Lock()
	defer b.lock.Unlock()

	return b.t
}
