package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type testMethodBodyNormal struct{}

type testMethodBodyCritical struct{}

func (tb testMethodBodyCritical) MethodMetadata() MethodMetadata {
	return MethodMetadata{
		Priority: MethodPriorityCritical,
	}
}

func TestMethodMetadata(t *testing.T) {
	require := require.New(t)

	methodNormal := NewMethodName("test", "Normal", testMethodBodyNormal{})
	methodCritical := NewMethodName("test", "Critical", testMethodBodyCritical{})
	require.False(methodNormal.IsCritical())
	require.True(methodCritical.IsCritical())
}
