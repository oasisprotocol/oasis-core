package abci

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

type testMessageKind uint8

var (
	testMessageA = testMessageKind(0)
	testMessageB = testMessageKind(1)
	testMessageC = testMessageKind(2)
)

type testMessage struct {
	foo int32
}

type errorMessage struct{}

var errTest = fmt.Errorf("error")

type testSubscriber struct {
	msgs []int32
	fail bool
}

// Implements api.MessageSubscriber.
func (s *testSubscriber) ExecuteMessage(ctx *api.Context, kind, msg interface{}) error {
	switch m := msg.(type) {
	case *testMessage:
		s.msgs = append(s.msgs, m.foo)
		if s.fail {
			return errTest
		}
		return nil
	case *errorMessage:
		return errTest
	default:
		panic("unexpected message was delivered")
	}
}

func TestMessageDispatcher(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := api.NewMockApplicationState(&api.MockApplicationStateConfig{})
	ctx := appState.NewContext(api.ContextBeginBlock, now)
	defer ctx.Close()

	var md messageDispatcher

	// Publish without subscribers should work.
	err := md.Publish(ctx, testMessageA, &testMessage{foo: 42})
	require.Error(err, "Publish")
	require.Equal(api.ErrNoSubscribers, err)

	// With a subscriber.
	var ms testSubscriber
	md.Subscribe(testMessageA, &ms)
	err = md.Publish(ctx, testMessageA, &testMessage{foo: 42})
	require.NoError(err, "Publish")
	require.EqualValues([]int32{42}, ms.msgs, "correct messages should be delivered")

	err = md.Publish(ctx, testMessageA, &testMessage{foo: 43})
	require.NoError(err, "Publish")
	require.EqualValues([]int32{42, 43}, ms.msgs, "correct messages should be delivered")

	err = md.Publish(ctx, testMessageB, &testMessage{foo: 44})
	require.Error(err, "Publish")
	require.Equal(api.ErrNoSubscribers, err)
	require.EqualValues([]int32{42, 43}, ms.msgs, "correct messages should be delivered")

	// Returning an error.
	err = md.Publish(ctx, testMessageA, &errorMessage{})
	require.Error(err, "Publish")
	require.True(errors.Is(err, errTest), "returned error should be the correct one")

	// Multiple subscribers.
	var ms2 testSubscriber
	md.Subscribe(testMessageA, &ms2)
	err = md.Publish(ctx, testMessageA, &testMessage{foo: 44})
	require.NoError(err, "Publish")
	require.EqualValues([]int32{42, 43, 44}, ms.msgs, "correct messages should be delivered")
	require.EqualValues([]int32{44}, ms2.msgs, "correct messages should be delivered")

	// Multiple subscribers, some succeed some fail.
	ms2.fail = true

	err = md.Publish(ctx, testMessageA, &testMessage{foo: 45})
	require.Error(err, "Publish")
	require.True(errors.Is(err, errTest), "returned error should be the correct one")
	require.EqualValues([]int32{42, 43, 44, 45}, ms.msgs, "correct messages should be delivered")
	require.EqualValues([]int32{44, 45}, ms2.msgs, "correct messages should be delivered")
}
