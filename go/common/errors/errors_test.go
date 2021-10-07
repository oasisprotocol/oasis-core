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
	module, code := Code(errTest1)
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.Equal("", Context(errTest1))

	module, code = Code(errTest2)
	require.Equal("test/errors", module)
	require.EqualValues(2, code)
	require.EqualValues("", Context(errTest2))

	// Map wrapped error to module and code.
	errTest3 := fmt.Errorf("wrapped: %w", errTest1)
	module, code = Code(errTest3)
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.EqualValues("", Context(errTest3))

	errTest4 := fmt.Errorf("wrapped: %w", errTest2)
	module, code = Code(errTest4)
	require.Equal("test/errors", module)
	require.EqualValues(2, code)
	require.EqualValues("", Context(errTest4))

	// Map error with context to module and code.
	errTest5 := WithContext(errTest1, "test context 1")
	module, code = Code(errTest5)
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.Equal("test context 1", Context(errTest5))

	errTest6 := fmt.Errorf("wrapped: %w", errTest5)
	module, code = Code(errTest6)
	require.Equal("test/errors", module)
	require.EqualValues(1, code)
	require.Equal("test context 1", Context(errTest6))

	// Map unknown error to module and code.
	errTest7 := fmt.Errorf("a different kind of error")
	module, code = Code(errTest7)
	require.Equal(UnknownModule, module)
	require.EqualValues(1, code)
	require.EqualValues("a different kind of error", errTest7.Error())

	// Map module and code to an error.
	err := FromCode("test/errors", 1, "test: this is an error")
	require.Equal(errTest1, err)
	err = FromCode("test/errors", 2, "test: this is an error")
	require.Equal(errTest2, err)
	err = FromCode("test/errors", 2, "test: this is an error: test context 2")
	require.True(Is(err, errTest2))
	require.Equal("test context 2", Context(err))
	err = FromCode("test/errors", 1, "if message gets clobbered somehow")
	require.Equal(WithContext(errTest1, "if message gets clobbered somehow"), err)

	// Unknown module and code.
	err = FromCode("test/does-not-exist", 5, "")
	require.Equal(New("test/does-not-exist", 5, ""), err)
	err = FromCode("test/errors", 3, "a test error occurred")
	require.Equal(New("test/errors", 3, "a test error occurred"), err)
}
