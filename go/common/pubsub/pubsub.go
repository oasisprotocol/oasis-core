// Package pubsub implements a generic publish-subscribe interface.
package pubsub

import (
	"errors"

	"github.com/eapache/channels"
)

type broadcastedValue struct {
	v interface{}
}

type cmdCtx struct {
	ch              *channels.InfiniteChannel
	errCh           chan error
	onSubscribeHook OnSubscribeHook

	isSubscribe bool
}

// Subscription is a Broker subscription instance.
type Subscription struct {
	b  *Broker
	ch *channels.InfiniteChannel
}

// Unwrap ties the read end of the provided channel to the subscription's
// output.
func (s *Subscription) Unwrap(ch interface{}) {
	channels.Unwrap(s.ch, ch)
}

// Close unsubscribes from the Broker.
func (s *Subscription) Close() {
	ctx := &cmdCtx{
		ch:          s.ch,
		errCh:       make(chan error),
		isSubscribe: false,
	}

	s.b.cmdCh <- ctx
	if err := <-ctx.errCh; err != nil {
		panic(err)
	}
}

// Broker is a pub/sub broker instance.
type Broker struct {
	subscribers     map[*channels.InfiniteChannel]bool
	cmdCh           chan *cmdCtx
	broadcastCh     chan interface{}
	lastBroadcasted *broadcastedValue

	onSubscribeHook OnSubscribeHook
}

// OnSubscribeHook is the on-subscribe callback hook prototype.
type OnSubscribeHook func(*channels.InfiniteChannel)

// Subscribe subscribes to the Broker's broadcasts, and returns a
// subscription handle that can be used to receive broadcasts.
//
// Note: The returned subscription's channel will have an unbounded
// capacity.
func (b *Broker) Subscribe() *Subscription {
	return b.SubscribeEx(nil)
}

// SubscribeEx subscribes to the Broker's broadcasts, and returns a
// subscription handle that can be used to receive broadcasts.  In
// addition it also takes a per-subscription on-subscribe callback
// hook.
//
// Note: The returned subscription's channel will have an unbounded
// capacity.  If there is a Broker wide hook set, it will be called
// after the per-subscription hook is called.
func (b *Broker) SubscribeEx(onSubscribeHook OnSubscribeHook) *Subscription {
	ctx := &cmdCtx{
		ch:              channels.NewInfiniteChannel(),
		errCh:           make(chan error),
		onSubscribeHook: onSubscribeHook,
		isSubscribe:     true,
	}

	b.cmdCh <- ctx
	<-ctx.errCh

	return &Subscription{
		b:  b,
		ch: ctx.ch,
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
				if ctx.onSubscribeHook != nil {
					ctx.onSubscribeHook(ctx.ch)
				}
				if b.onSubscribeHook != nil {
					b.onSubscribeHook(ctx.ch)
				}
				b.subscribers[ctx.ch] = true
				close(ctx.errCh)
			} else {
				if !b.subscribers[ctx.ch] {
					ctx.errCh <- errors.New("pubsub: unsubscribed an unknown channel")
				} else {
					delete(b.subscribers, ctx.ch)
					ctx.ch.Close() // Close the no longer subscribed channel.
					close(ctx.errCh)
				}
			}
		case v := <-b.broadcastCh:
			for ch := range b.subscribers {
				ch.In() <- v
			}
			b.lastBroadcasted = &broadcastedValue{v}
		}
	}
}

// NewBroker creates a new pub/sub broker.  If pubLastOnSubscribe is set,
// the last broadcasted value will automatically be published to new
// subscribers, if one exists.
func NewBroker(pubLastOnSubscribe bool) *Broker {
	b := newBroker()
	if pubLastOnSubscribe {
		b.onSubscribeHook = func(ch *channels.InfiniteChannel) {
			if b.lastBroadcasted != nil {
				ch.In() <- b.lastBroadcasted.v
			}
		}
	}

	go b.worker()

	return b
}

// NewBrokerEx creates a new pub/sub broker, with a hook to be called
// when a new subscriber is registered.
func NewBrokerEx(onSubscribeHook OnSubscribeHook) *Broker {
	b := newBroker()
	b.onSubscribeHook = onSubscribeHook

	go b.worker()

	return b
}

func newBroker() *Broker {
	return &Broker{
		subscribers: make(map[*channels.InfiniteChannel]bool),
		cmdCh:       make(chan *cmdCtx),
		broadcastCh: make(chan interface{}),
	}
}
