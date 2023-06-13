package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtquery "github.com/cometbft/cometbft/libs/pubsub/query"
)

func TestServiceDescriptor(t *testing.T) {
	require := require.New(t)

	q1 := cmtquery.MustParse("a='b'")

	sd := NewStaticServiceDescriptor("test", "test_type", []cmtpubsub.Query{q1})
	require.Equal("test", sd.Name())
	require.Equal("test_type", sd.EventType())
	recvQ1 := <-sd.Queries()
	require.EqualValues(q1, recvQ1, "received query should be correct")
	_, ok := <-sd.Queries()
	require.False(ok, "query channel must be closed")
}
