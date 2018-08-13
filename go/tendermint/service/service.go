// Package service provides the tendermint service interface.
package service

import (
	tmcli "github.com/tendermint/tendermint/rpc/client"

	"github.com/oasislabs/ekiden/go/common/service"
)

// TendermintService provides Tendermint access to Ekiden backends.
type TendermintService interface {
	service.BackgroundService

	// GetClient creates a Tendermint client that talks to this service instance.
	GetClient() tmcli.Client
}
