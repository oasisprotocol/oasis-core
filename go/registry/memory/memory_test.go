package memory

import (
	"testing"

	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/registry/tests"
)

func TestRegistryMemory(t *testing.T) {
	timeSource := mock.New()
	backend := New(timeSource)
	defer backend.Cleanup()

	tests.RegistryImplementationTests(t, backend, timeSource)
}
