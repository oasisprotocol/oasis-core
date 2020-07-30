// Oasis node implementation.
package main

import (
	"github.com/hashicorp/go-plugin"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd"
)

func main() {
	// If we use go-plugin, we are supposed to clean clients up.
	defer plugin.CleanupClients()

	cmd.Execute()
}
