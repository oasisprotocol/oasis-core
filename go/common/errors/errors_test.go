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

	module, code = Code(errTest2)
	require.Equal("test/errors", module)
	require.EqualValues(2, code)

	// Map wrapped error to module and code.
	module, code = Code(fmt.Errorf("wrapped: %w", errTest1))
	require.Equal("test/errors", module)
	require.EqualValues(1, code)

	module, code = Code(fmt.Errorf("wrapped: %w", errTest2))
	require.Equal("test/errors", module)
	require.EqualValues(2, code)

	// Map unknown error to module and code.
	module, code = Code(fmt.Errorf("a different kind of error"))
	require.Equal(UnknownModule, module)
	require.EqualValues(1, code)

	// Map module and code to an error.
	err := FromCode("test/errors", 1)
	require.Equal(errTest1, err)
	err = FromCode("test/errors", 2)
	require.Equal(errTest2, err)

	// Unknown module and code.
	err = FromCode("test/does-not-exist", 5)
	require.Nil(err)
	err = FromCode("test/errors", 3)
	require.Nil(err)
}
