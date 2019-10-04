package integrationrunner

import (
	"flag"
	"testing"
)

var run = flag.Bool("integration.run", false, "Run the node")

func TestIntegration(t *testing.T) {
	if !*run {
		t.Skip("Pass -integration.run to run the node")
		return
	}

	launch()
}
