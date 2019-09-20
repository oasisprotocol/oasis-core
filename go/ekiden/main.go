// Ekiden node implementation.
package main

import (
	"syscall"

	"github.com/oasislabs/ekiden/go/ekiden/cmd"
)

func main() {
	// Only the owner should have read/write/execute permissions for
	// anything created by the ekiden binary.
	syscall.Umask(0077)

	cmd.Execute()
}
