package logging

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilterLogger(t *testing.T) {
	require := require.New(t)

	var buffer bytes.Buffer
	logger := NewJSONLogger(&buffer)
	logger = NewFilterLogger(logger, map[any]struct{}{
		"foo": {},
	})
	logger.Info("this is a test", "bar", 42, "foo", 17)

	const expectedOutput = `{"bar":42,"level":"info","msg":"this is a test"}` + "\n"
	require.Equal(expectedOutput, buffer.String())
}
