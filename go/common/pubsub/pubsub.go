// Package pubsub implements a generic publish-subscribe interface.
package pubsub

import (
	"context"
	"errors"

	"github.com/eapache/channels"
)

type broadcastedValue struct {
	v interface{}
}

type cmdCtx struct {
	ch              channels.Channel
	errCh           chan error
	onSubscribeHook OnSubscribeHook

	isSubscribe bool
}

// ClosableSubscription is an interface for a subscription that can be
// closed. This can be used as return value from methods instead of the
// actual Subscription to expose a more limited interface.
type ClosableSubscription interface {
	// Close unsubscribes the subscription.
	Close()
}

type contextSubscription struct {
	cancel context.CancelFunc
}

func (s contextSubscription) Close() {
	s.cancel()
}

// NewContextSubscription creates a subscription that cancels the context
// when closed.
func NewContextSubscription(ctx context.Context) (context.Context, ClosableSubscription) {
	ctx, cancel := context.WithCancel(ctx)
	return ctx, contextSubscription{cancel}
}

// Subscription is a Broker subscription instance.
type Subscription struct {
	b  *Broker
	ch channels.Channel
}

// Untyped returns the subscription's untyped output.  Effort should be
// made to use Unwrap instead.
func (s *Subscription) Untyped() <-chan interface{} {
	return s.ch.Out()
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
	subscribers     map[channels.Channel]bool
	cmdCh           chan *cmdCtx
	broadcastCh     channels.Channel
	lastBroadcasted *broadcastedValue

	onSubscribeHook OnSubscribeHook
}

// OnSubscribeHook is the on-subscribe callback hook prototype.
type OnSubscribeHook func(channels.Channel)

// Subscribe subscribes to the Broker's broadcasts, and returns a
// subscription handle that can be used to receive broadcasts.
//
// Note: The returned subscription's channel will have an unbounded
// capacity, use SubscribeBuffered to use a bounded ring channel.
func (b *Broker) Subscribe() *Subscription {
	return b.SubscribeEx(int64(channels.Infinity), nil)
}

// SubscribeBuffered subscribes to the Broker's broadcasts, and returns a
// subscription handle that can be used to receive broadcasts.
//
// Buffer controls the capacity of a ring buffer - when buffer is full the
// oldest value will be discarded. In case buffer is negative (or zero) an
// unbounded channel is used.
func (b *Broker) SubscribeBuffered(buffer int64) *Subscription {
	return b.SubscribeEx(buffer, nil)
}

// SubscribeEx subscribes to the Broker's broadcasts, and returns a
// subscription handle that can be used to receive broadcasts.  In
// addition it also takes a per-subscription on-subscribe callback
// hook.
//
// Note: If there is a Broker wide hook set, it will be called
// after the per-subscription hook is called.
func (b *Broker) SubscribeEx(buffer int64, onSubscribeHook OnSubscribeHook) *Subscription {
	var ch channels.Channel
	if buffer <= 0 {
		ch = channels.NewInfiniteChannel()
	} else {
		ch = channels.NewRingChannel(channels.BufferCap(buffer))
	}
	ctx := &cmdCtx{
		ch:              ch,
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
	b.broadcastCh.In() <- v
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
		case v := <-b.broadcastCh.Out():
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
		b.onSubscribeHook = func(ch channels.Channel) {
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
		subscribers: make(map[channels.Channel]bool),
		cmdCh:       make(chan *cmdCtx),
		broadcastCh: channels.NewInfiniteChannel(),
	}
}
