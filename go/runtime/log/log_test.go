package log

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLog(t *testing.T) {
	require := require.New(t)

	tmpDir := t.TempDir()
	logFn := filepath.Join(tmpDir, "log")
	log, err := NewLog(logFn, 1024)
	require.NoError(err, "newLog")
	defer log.Close()

	logger := log.Logger()
	logger.Info("hello info world", "ts", "2025-05-26T10:45:06.755286713Z")
	logger.Warn("hello warn world", "ts", "2025-05-26T10:46:06.755286713Z")
	logger.Error("hello error world", "ts", "2025-05-26T10:47:06.755286713Z")

	ctx, cancelFn := context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()
	lines, err := log.Read(ctx, WatchOptions{Follow: false})
	require.NoError(err, "log.Watch")

	expectedOutput := []string{
		`{"level":"info","msg":"hello info world","ts":"2025-05-26T10:45:06.755286713Z"}`,
		`{"level":"warn","msg":"hello warn world","ts":"2025-05-26T10:46:06.755286713Z"}`,
		`{"level":"error","msg":"hello error world","ts":"2025-05-26T10:47:06.755286713Z"}`,
	}
	require.Equal(expectedOutput, lines)

	// Test with filtering by timestamp.
	ctx, cancelFn = context.WithTimeout(context.Background(), time.Second)
	defer cancelFn()
	lines, err = log.Read(ctx, WatchOptions{Follow: false, Since: time.Date(2025, 5, 26, 10, 47, 0, 0, time.UTC)})
	require.NoError(err, "log.Watch")

	expectedOutput = []string{
		`{"level":"error","msg":"hello error world","ts":"2025-05-26T10:47:06.755286713Z"}`,
	}
	require.Equal(expectedOutput, lines)
}
