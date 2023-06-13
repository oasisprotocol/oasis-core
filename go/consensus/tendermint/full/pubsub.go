package full

import (
	"github.com/eapache/channels"

	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"
)

var _ cmttypes.Subscription = (*tendermintPubsubBuffer)(nil)

// tendermintPubsubBuffer is a wrapper around tendermint subscriptions.
// Because unbuffered subscriptions are dangerous and can lead to deadlocks
// if they're not drained, this wrapper shunts all events into its own buffer.
type tendermintPubsubBuffer struct {
	messageBuffer  *channels.InfiniteChannel
	tmSubscription cmttypes.Subscription
	outCh          chan cmtpubsub.Message
	cancelCh       chan struct{}
}

func newTendermintPubsubBuffer(tmSubscription cmttypes.Subscription) *tendermintPubsubBuffer {
	ps := &tendermintPubsubBuffer{
		messageBuffer:  channels.NewInfiniteChannel(),
		tmSubscription: tmSubscription,
		outCh:          make(chan cmtpubsub.Message),
		cancelCh:       make(chan struct{}),
	}

	go ps.reader()
	go ps.writer()

	return ps
}

func (ps *tendermintPubsubBuffer) Out() <-chan cmtpubsub.Message {
	return ps.outCh
}

func (ps *tendermintPubsubBuffer) Cancelled() <-chan struct{} {
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
		case <-ps.tmSubscription.Cancelled():
			return
		}
	}
}

func (ps *tendermintPubsubBuffer) writer() {
	for msg := range ps.messageBuffer.Out() {
		ps.outCh <- *(msg.(*cmtpubsub.Message))
	}
}
