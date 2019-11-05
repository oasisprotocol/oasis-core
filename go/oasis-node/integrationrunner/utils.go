package integrationrunner

import (
	"os"

	"github.com/oasislabs/oasis-core/go/oasis-node/cmd"
)

func trimArgs(words []string) []string {
	for i, w := range words {
		if w == "--" {
			return words[i:]
		}
	}
	return nil
}

func launch() {
	os.Args = trimArgs(os.Args)
	cmd.Execute()
}
