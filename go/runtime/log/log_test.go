package log

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLog(t *testing.T) {
	require := require.New(t)

	tmpDir := t.TempDir()
	logFn := filepath.Join(tmpDir, "log")
	log, err := newLog(logFn, 1024)
	require.NoError(err, "newLog")
	defer log.Close()

	logger := log.Logger()
	logger.Info("hello log world")

	var (
		lines []string
		wg    sync.WaitGroup
	)
	ch := make(chan string)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range ch {
			lines = append(lines, line)
		}
	}()

	err = log.Watch(context.Background(), ch, false)
	require.NoError(err, "log.Watch")
	close(ch)
	wg.Wait()

	const expectedOutput = `{"level":"info","msg":"hello log world"}`
	require.Len(lines, 1)
	require.Equal(expectedOutput, lines[0])
}
