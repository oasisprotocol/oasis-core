// Oasis node implementation.
package main

import (
	"syscall"

	"github.com/oasislabs/oasis-core/go/oasis-node/cmd"
)

func main() {
	// Only the owner should have read/write/execute permissions for
	// anything created by the oasis-node binary.
	syscall.Umask(0077)

	cmd.Execute()
}
