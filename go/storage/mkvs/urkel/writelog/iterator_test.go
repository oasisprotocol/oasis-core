package writelog

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	writeLogSize = 100
)

func makeWriteLog() WriteLog {
	wl := make(WriteLog, writeLogSize)

	for i := 0; i < writeLogSize; i++ {
		wl[i] = LogEntry{
			Key:   []byte(fmt.Sprintf("key %d", i)),
			Value: []byte(fmt.Sprintf("value %d", i)),
		}
	}

	return wl
}

func TestStaticIterator(t *testing.T) {
	var more bool
	var err error
	var val LogEntry

	wl := makeWriteLog()

	it := NewStaticIterator(wl)

	for _, ent := range wl {
		more, err = it.Next()
		require.NoError(t, err, "it.Next()")
		require.Equal(t, more, true)
		val, err = it.Value()
		require.NoError(t, err, "it.Value()")
		require.Equal(t, val, ent)
	}
	more, err = it.Next()
	require.NoError(t, err, "last it.Next()")
	require.Equal(t, more, false)
	_, err = it.Value()
	require.Error(t, err, "last it.Value()")

	var wl2 WriteLog
	it = NewStaticIterator(wl2)
	more, err = it.Next()
	require.NoError(t, err, "empty it.Next()")
	require.Equal(t, more, false)
}

func TestPipeIterator(t *testing.T) {
	var err error
	var more bool
	var val LogEntry

	wl := makeWriteLog()
	pipe := NewPipeIterator(context.Background())

	for idx := range wl {
		err = pipe.Put(&wl[idx])
		require.NoError(t, err, "pipe.Put()")
	}
	pipe.Close()

	for _, ent := range wl {
		more, err = pipe.Next()
		require.NoError(t, err, "pipe.Next()")
		require.Equal(t, more, true)
		val, err = pipe.Value()
		require.NoError(t, err, "pipe.Value()")
		require.Equal(t, val, ent)
	}
	more, err = pipe.Next()
	require.NoError(t, err, "last pipe.Next()")
	require.Equal(t, more, false)
	_, err = pipe.Value()
	require.Error(t, err, "last pipe.Value()")
}
