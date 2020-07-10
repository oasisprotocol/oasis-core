package pubsub

import (
	"testing"
	"time"

	"github.com/eapache/channels"
	"github.com/stretchr/testify/require"
)

const (
	recvTimeout = 5 * time.Second
	bufferSize  = 5
)

func TestPubSub(t *testing.T) {
	t.Run("BasicInfinity", testBasicInfinity)
	t.Run("BasicOverwriting", testBasicOverwriting)
	t.Run("PubLastOnSubscribe", testLastOnSubscribe)
	t.Run("SubscribeEx", testSubscribeEx)
	t.Run("NewBrokerEx", testNewBrokerEx)
}

func testBasicInfinity(t *testing.T) {
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

func testBasicOverwriting(t *testing.T) {
	broker := NewBroker(false)

	sub := broker.SubscribeBuffered(bufferSize)
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

	// Test the buffered nature of the overwriting channel.
	for i := 0; i < bufferSize+10; i++ {
		broker.Broadcast(i)
	}
	// Ensure we don't start reading before all messages are processed by the
	// underlying channel.
	time.Sleep(100 * time.Millisecond)

	// RingChannel prefers to write before buffering the items, so the first
	// element will be instantly send to the output channel and removed from the
	// buffer so it will not get overwritten.
	expected := []int{
		0,
	}
	for i := 10; i < bufferSize+10; i++ {
		expected = append(expected, i)
	}
	for _, i := range expected {
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

	for _, b := range []int64{
		int64(channels.Infinity),
		bufferSize,
	} {
		sub := broker.SubscribeBuffered(b)
		typedCh := make(chan int)
		sub.Unwrap(typedCh)

		select {
		case v := <-typedCh:
			require.Equal(t, 23, v, "Last Broadcast()")
		case <-time.After(recvTimeout):
			t.Fatalf("Failed to receive value, last Broadcast() on Subscribe()")
		}
	}
}

func testSubscribeEx(t *testing.T) {
	broker := NewBroker(false)
	var callbackCh channels.Channel
	callback := func(ch channels.Channel) {
		callbackCh = ch
	}

	for _, b := range []int64{
		int64(channels.Infinity),
		bufferSize,
	} {
		sub := broker.SubscribeEx(b, callback)

		require.NotNil(t, sub.ch, "Subscription, inner channel")
		require.Equal(t, sub.ch, callbackCh, "Callback channel != Subscription, inner channel")
	}
}

func testNewBrokerEx(t *testing.T) {
	var callbackCh channels.Channel
	broker := NewBrokerEx(func(ch channels.Channel) {
		callbackCh = ch
	})

	for _, b := range []int64{
		int64(channels.Infinity),
		bufferSize,
	} {
		sub := broker.SubscribeBuffered(b)
		require.NotNil(t, sub.ch, "Subscription, inner channel")
		require.Equal(t, sub.ch, callbackCh, "Callback channel != Subscription, inner channel")
	}
}
