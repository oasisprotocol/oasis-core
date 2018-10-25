package mock

import (
	"testing"

	"github.com/oasislabs/ekiden/go/epochtime/tests"
)

func TestEpochtimeMock(t *testing.T) {
	tests.EpochtimeSetableImplementationTest(t, New())
}
