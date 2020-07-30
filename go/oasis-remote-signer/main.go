// Oasis remote signer implementation.
package main

import (
	"github.com/hashicorp/go-plugin"

	"github.com/oasisprotocol/oasis-core/go/oasis-remote-signer/cmd"
)

func main() {
	// If we use go-plugin, we are supposed to clean clients up.
	defer plugin.CleanupClients()

	cmd.Execute()
}
