package pubsub

import (
	"testing"
	"time"

	"github.com/eapache/channels"
	"github.com/stretchr/testify/require"
)

const recvTimeout = 5 * time.Second

func TestPubSub(t *testing.T) {
	t.Run("Basic", testBasic)
	t.Run("PubLastOnSubscribe", testLastOnSubscribe)
	t.Run("SubscribeEx", testSubscribeEx)
	t.Run("NewBrokerEx", testNewBrokerEx)
}

func testBasic(t *testing.T) {
	broker := NewBroker(false)

	sub := broker.Subscribe()
	typedCh := make(chan int)
	sub.Unwrap(typedCh)

	// Test a single broadcast/receive.
	broker.Broadcast(23)
	select {
	case v := <-typedCh:
		require.Equal(t, 23, v, "Single Broadcast())")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive value, initial Broadcast()")
	}

	// Test the buffered nature of the subscription channel.
	for i := 0; i < 10; i++ {
		broker.Broadcast(i)
	}
	for i := 0; i < 10; i++ {
		select {
		case v := <-typedCh:
			require.Equal(t, i, v, "Buffered Broadcast()")
		case <-time.After(recvTimeout):
			t.Fatalf("Failed to receive value, buffered Broadcast()")
		}
	}

	require.NotPanics(t, func() { sub.Close() }, "Close()")
	require.Len(t, broker.subscribers, 0, "Subscriber map, post Close()")
}

func testLastOnSubscribe(t *testing.T) {
	broker := NewBroker(true)
	broker.Broadcast(23)

	sub := broker.Subscribe()
	typedCh := make(chan int)
	sub.Unwrap(typedCh)

	select {
	case v := <-typedCh:
		require.Equal(t, 23, v, "Last Broadcast()")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive value, last Broadcast() on Subscribe()")
	}
}

func testSubscribeEx(t *testing.T) {
	broker := NewBroker(false)

	var callbackCh *channels.InfiniteChannel
	sub := broker.SubscribeEx(func(ch *channels.InfiniteChannel) {
		callbackCh = ch
	})

	require.NotNil(t, sub.ch, "Subscription, inner channel")
	require.Equal(t, sub.ch, callbackCh, "Callback channel != Subscription, inner channel")
}

func testNewBrokerEx(t *testing.T) {
	var callbackCh *channels.InfiniteChannel
	broker := NewBrokerEx(func(ch *channels.InfiniteChannel) {
		callbackCh = ch
	})

	sub := broker.Subscribe()
	require.NotNil(t, sub.ch, "Subscription, inner channel")
	require.Equal(t, sub.ch, callbackCh, "Callback channel != Subscription, inner channel")
}
