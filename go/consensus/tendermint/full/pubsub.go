package full

import (
	"github.com/eapache/channels"

	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmtypes "github.com/tendermint/tendermint/types"
)

var _ tmtypes.Subscription = (*tendermintPubsubBuffer)(nil)

// tendermintPubsubBuffer is a wrapper around tendermint subscriptions.
// Because unbuffered subscriptions are dangerous and can lead to deadlocks
// if they're not drained, this wrapper shunts all events into its own buffer.
type tendermintPubsubBuffer struct {
	messageBuffer  *channels.InfiniteChannel
	tmSubscription tmtypes.Subscription
	outCh          chan tmpubsub.Message
	cancelCh       chan struct{}
}

func newTendermintPubsubBuffer(tmSubscription tmtypes.Subscription) *tendermintPubsubBuffer {
	ps := &tendermintPubsubBuffer{
		messageBuffer:  channels.NewInfiniteChannel(),
		tmSubscription: tmSubscription,
		outCh:          make(chan tmpubsub.Message),
		cancelCh:       make(chan struct{}),
	}

	go ps.reader()
	go ps.writer()

	return ps
}

func (ps *tendermintPubsubBuffer) ID() string {
	return ps.tmSubscription.ID()
}

func (ps *tendermintPubsubBuffer) Out() <-chan tmpubsub.Message {
	return ps.outCh
}

func (ps *tendermintPubsubBuffer) Canceled() <-chan struct{} {
	return ps.cancelCh
}

func (ps *tendermintPubsubBuffer) Err() error {
	return ps.tmSubscription.Err()
}

func (ps *tendermintPubsubBuffer) reader() {
	defer close(ps.cancelCh)
	defer ps.messageBuffer.Close()

	for {
		select {
		case msg, ok := <-ps.tmSubscription.Out():
			if !ok {
				return
			}
			ps.messageBuffer.In() <- &msg
		case <-ps.tmSubscription.Canceled():
			return
		}
	}
}

func (ps *tendermintPubsubBuffer) writer() {
	for msg := range ps.messageBuffer.Out() {
		ps.outCh <- *(msg.(*tmpubsub.Message))
	}
}
