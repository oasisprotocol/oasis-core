package memory

import (
	"testing"

	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage/internal/tester"
)

func TestStorageMemory(t *testing.T) {
	timeSource := mock.New()
	backend := New(timeSource)
	defer backend.Cleanup()

	tester.StorageImplementationTest(t, backend, timeSource)
}
