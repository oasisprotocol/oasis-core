package host

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

func TestRuntimeLogWrapper(t *testing.T) {
	require := require.New(t)

	// Redirect all logs to a buffer where we can inspect them later.
	// Use JSON format because it uses a deterministic (a-z) order of keys.
	var buf bytes.Buffer
	_ = logging.Initialize(&buf, logging.FmtJSON, logging.LevelDebug, map[string]logging.Level{})

	// Simulated runtime output.
	logChunks := []string{
		// A message in multiple chunks
		`{"msg":"Runtime is starti`, `ng","level":"INFO","ts":"2022-04-26","module":"runtime"}
		`,
		// A message with multiple chunks, one of them being just the terminating newline
		`{`, `"msg":"My info\nwith a newline","level":"INFO","ts":"2022","module":"runtime"}`, "\n",
		// A chunk containing multiple messages
		`{"msg":"My debug","level":"DEBG","ts":"2022-04-27","module":"runtime/dispatcher"}
		{"msg":"My error","lev`, `e`, `l":"ERRO","ts":"2022-04-28","module":"runtime/protocol","err":"some explanation"}
		`,
		// Malformed (non-JSON) output
		"Random crap\n",
		// One more valid JSON to make sure we've recovered. Also tests non-"runtime"-scoped module name.
		`{"msg":"Should be recovered","level":"INFO","ts":"2022","module":"foo"`, "}\n",
	}

	// Feed data to RuntimeLogWrapper.
	w := NewRuntimeLogWrapper(logging.GetLogger("testenv"))
	for _, chunk := range logChunks {
		n, err := w.Write([]byte(chunk))
		require.Equal(len(chunk), n)
		require.NoError(err)
	}

	actual := strings.Split(buf.String(), "\n")
	expected := []string{
		`{"level":"info","module":"runtime","msg":"Runtime is starting","ts":"2022-04-26"}`,
		`{"level":"info","module":"runtime","msg":"My info\\nwith a newline","ts":"2022"}`,
		`{"level":"debug","module":"runtime/dispatcher","msg":"My debug","ts":"2022-04-27"}`,
		`{"err":"some explanation","level":"error","module":"runtime/protocol","msg":"My error","ts":"2022-04-28"}`,
		`{"level":"warn","module":"runtime","msg":"\\t\\tRandom crap","ts":"[^"]+"}`,
		`{"level":"info","module":"runtime/foo","msg":"Should be recovered","ts":"2022"}`,
		``, // Because we split on newline and the last log entry ends with a newline
	}

	require.EqualValues(
		len(expected), len(actual),
		"Unexpected number of log entries; expected %d, got %d: %#v",
		len(expected), len(actual), actual)
	for i := range actual {
		require.Regexp(
			expected[i], actual[i],
			"Log line %2d was        %#v\nbut should match regex %#v",
			i+1, actual[i], expected[i])
	}
}
