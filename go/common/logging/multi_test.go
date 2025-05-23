package logging

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMultiLogger(t *testing.T) {
	require := require.New(t)

	var (
		bufferA bytes.Buffer
		bufferB bytes.Buffer
	)
	loggerA := NewJSONLogger(&bufferA)
	loggerB := NewJSONLogger(&bufferB)
	multi := NewMultiLogger(loggerA, loggerB)
	multi.Info("this is a test", "foo", 3)

	const expectedOutput1 = `{"foo":3,"level":"info","msg":"this is a test"}` + "\n"
	require.Equal(expectedOutput1, bufferA.String())
	require.Equal(expectedOutput1, bufferB.String())

	var bufferC bytes.Buffer
	loggerC := NewJSONLogger(&bufferC).With("module", "test")
	loggerC.module = "test"
	multi = NewMultiLogger(loggerC, loggerB)
	bufferB.Reset()
	multi.Info("this is another test", "foo", 42)

	const expectedOutput2 = `{"foo":42,"level":"info","module":"test","msg":"this is another test"}` + "\n"
	require.Equal(expectedOutput2, bufferB.String())
	require.Equal(expectedOutput2, bufferC.String())
}
