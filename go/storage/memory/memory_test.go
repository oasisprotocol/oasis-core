package memory

import (
	"testing"

	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

func TestStorageMemory(t *testing.T) {
	timeSource := mock.New()
	backend := New(timeSource, nil)
	defer backend.Cleanup()

	tests.StorageImplementationTests(t, backend, timeSource, true)
}
