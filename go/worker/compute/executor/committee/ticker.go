package committee

import (
	"time"
)

// RankTicker represents an interface for rank ticker functionality.
type RankTicker interface {
	// Start starts the ticker.
	Start()

	// Stop stops the ticker.
	Stop()

	// C returns a channel on which ranks will be sent.
	C() <-chan uint64
}

type linearRankTicker struct {
	c chan uint64

	stop chan struct{}
	done chan struct{}

	timestamp int64
	duration  time.Duration
	maxRank   uint64
}

// NewLinearRankTicker returns a new linear rank ticker.
func NewLinearRankTicker(timestamp uint64, d time.Duration, maxRank uint64) RankTicker {
	if d <= 0 {
		panic("duration has to be a positive number")
	}

	return &linearRankTicker{
		c:         make(chan uint64, 1),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		timestamp: int64(timestamp),
		duration:  d,
		maxRank:   maxRank,
	}
}

func (t *linearRankTicker) C() <-chan uint64 {
	return t.c
}

func (t *linearRankTicker) Start() {
	go t.start()
}

func (t *linearRankTicker) start() {
	defer close(t.done)

	var rank uint64
	sendRank := func() {
		select {
		case t.c <- rank:
		default:
		}
		rank++
	}

	diff := time.Until(time.Unix(t.timestamp, 0))
	if diff < 0 {
		rank = uint64(-diff / t.duration)
		if rank > t.maxRank {
			rank = t.maxRank
		}

		sendRank()
		if rank > t.maxRank {
			return
		}

		diff = t.duration + diff%t.duration
	}

	timer := time.NewTimer(diff)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-t.stop:
		return
	}

	ticker := time.NewTicker(t.duration)
	defer ticker.Stop()

	for {
		sendRank()
		if rank > t.maxRank {
			return
		}

		select {
		case <-ticker.C:
		case <-t.stop:
			return
		}
	}
}

func (t *linearRankTicker) Stop() {
	close(t.stop)
	<-t.done
}
