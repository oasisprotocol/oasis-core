package integrationrunner

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var run = flag.Bool("integration.run", false, "Run the node")

func TestIntegration(t *testing.T) {
	if !*run {
		// This test requires a bunch of extra arguments and isn't automated on its own. Because of that, it's disabled
		// by default. This way, running `go test` with ./... works with no fuss.
		t.Skip("Pass -integration.run to run the node")
		return
	}

	launch()

	// Suppress coverage report on stdout.
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	require.NoError(t, err, "opening %s", os.DevNull)
	os.Stdout = f
}
