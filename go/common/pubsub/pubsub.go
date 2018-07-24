// Package pubsub implements a generic publish-subscribe interface.
package pubsub

import "errors"

type broadcastedValue struct {
	v interface{}
}

type cmdCtx struct {
	ch    chan interface{}
	errCh chan error

	isSubscribe bool
}

// Broker is a pub/sub broker instance.
type Broker struct {
	subscribers     map[chan interface{}]bool
	cmdCh           chan *cmdCtx
	broadcastCh     chan interface{}
	lastBroadcasted *broadcastedValue

	pubLastOnSubscribe bool
}

// Subscribe subscribes to the Broker's broadcasts, and returns a
// channel that can be used to receive broadcasts.
//
// If the Broker is so configured, the last broadcsted value will
// be automatically sent via the channel immediately.
//
// Note: The returned channel will have a capacity of 1.
func (b *Broker) Subscribe() chan interface{} {
	ctx := &cmdCtx{
		ch:          make(chan interface{}, 1),
		errCh:       make(chan error),
		isSubscribe: true,
	}

	b.cmdCh <- ctx
	<-ctx.errCh

	return ctx.ch
}

// Unsubscribe unsubscribes from the Broker's broadcasts, and closes
// the channel.
func (b *Broker) Unsubscribe(ch chan interface{}) {
	ctx := &cmdCtx{
		ch:          ch,
		errCh:       make(chan error),
		isSubscribe: false,
	}

	b.cmdCh <- ctx
	if err := <-ctx.errCh; err != nil {
		panic(err)
	}
}

// Broadcast queues up a new value to be broadcasted.
//
// Note: This makes no special effort to avoid deadlocking if any one
// of the subscribers' channel is full.
func (b *Broker) Broadcast(v interface{}) {
	b.broadcastCh <- v
}

func (b *Broker) worker() {
	for {
		select {
		case ctx := <-b.cmdCh:
			if ctx.isSubscribe {
				if b.pubLastOnSubscribe && b.lastBroadcasted != nil {
					ctx.ch <- b.lastBroadcasted.v
				}
				b.subscribers[ctx.ch] = true
				close(ctx.errCh)
			} else {
				if !b.subscribers[ctx.ch] {
					ctx.errCh <- errors.New("pubsub: unsubscribed an unknown channel")
				} else {
					delete(b.subscribers, ctx.ch)
					close(ctx.ch) // Close the no longer subscribed channel.
					close(ctx.errCh)
				}
			}
		case v := <-b.broadcastCh:
			for ch := range b.subscribers {
				ch <- v
			}
			if b.pubLastOnSubscribe {
				b.lastBroadcasted = &broadcastedValue{v}
			}
		}
	}
}

// NewBroker creates a new pub/sub broker.  If pubLastOnSubscribe is set,
// the last broadcasted value will automatically be published to new
// subscribers, if one exists.
func NewBroker(pubLastOnSubscribe bool) *Broker {
	b := &Broker{
		subscribers:        make(map[chan interface{}]bool),
		cmdCh:              make(chan *cmdCtx),
		broadcastCh:        make(chan interface{}),
		pubLastOnSubscribe: pubLastOnSubscribe,
	}

	go b.worker()

	return b
}
