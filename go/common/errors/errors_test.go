package errors

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrors(t *testing.T) {
	require := require.New(t)

	// Make sure an error can be registered.
	var errTest1, errTest2 error
	require.NotPanics(func() { errTest1 = New("test/errors", 1, "test: this is an error") })
	require.NotPanics(func() { errTest2 = New("test/errors", 2, "test: this is an error") })

	// Make sure the zero error code cannot be registered.
	require.Panics(func() { _ = New("test/errors", 0, "test: this is another error") })

	// Make sure we panic if the same error code is registered twice.
	require.Panics(func() { _ = New("test/errors", 1, "test: this is another error") })

	// Map error to module and code.
	module, code, context := Code(errTest1)
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.Equal(context, "")

	module, code, context = Code(errTest2)
	require.Equal("test/errors", module)
	require.EqualValues(2, code)
	require.EqualValues(context, "")

	// Map wrapped error to module and code.
	module, code, context = Code(fmt.Errorf("wrapped: %w", errTest1))
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.EqualValues(context, "")

	module, code, context = Code(fmt.Errorf("wrapped: %w", errTest2))
	require.Equal("test/errors", module)
	require.EqualValues(2, code)
	require.EqualValues(context, "")

	// Map error with context to module and code.
	module, code, context = Code(WithContext(errTest1, "test context 1"))
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.Equal(context, "test context 1")

	module, code, context = Code(fmt.Errorf("wrapped: %w", WithContext(errTest1, "test context 1")))
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.Equal(context, "test context 1")

	// Map unknown error to module and code.
	module, code, context = Code(fmt.Errorf("a different kind of error"))
	require.Equal(UnknownModule, module)
	require.EqualValues(1, code)
	require.EqualValues("a different kind of error", context)

	// Map module and code to an error.
	err := FromCode("test/errors", 1, "")
	require.Equal(errTest1, err)
	err = FromCode("test/errors", 2, "")
	require.Equal(errTest2, err)
	err = FromCode("test/errors", 2, "test context 2")
	require.True(Is(err, errTest2))
	require.Equal("test context 2", Context(err))

	// Unknown module and code.
	err = FromCode("test/does-not-exist", 5, "")
	require.Equal(err, New("test/does-not-exist", 5, ""))
	err = FromCode("test/errors", 3, "a test error occurred")
	require.Equal(err, WithContext(New("test/errors", 3, "a test error occurred"), "a test error occurred"))
}
