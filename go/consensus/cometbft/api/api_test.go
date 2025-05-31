package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	cmtquery "github.com/cometbft/cometbft/libs/pubsub/query"
)

func TestServiceDescriptor(t *testing.T) {
	require := require.New(t)

	q1 := cmtquery.MustParse("a='b'")

	sd := NewServiceDescriptor("test", "test_type", 1)
	sd.AddQuery(q1)
	require.Equal("test", sd.Name())
	require.Equal("test_type", sd.EventType())
	recvQ1 := <-sd.Queries()
	require.EqualValues(q1, recvQ1, "received query should be correct")
}
