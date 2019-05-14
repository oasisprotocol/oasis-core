// Package client implements the key manager client.
package client

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/worker/common/enclaverpc"
)

const (
	// XXX: Remove once we automatically discover the key manager for each runtime.
	cfgClientAddress = "keymanager.client.address"
	cfgClientCert    = "keymanager.client.certificate"
)

// Client is a key manager client instance.
type Client struct {
	client *enclaverpc.Client
}

// CallRemote calls a runtime-specific key manager via remote EnclaveRPC.
func (c *Client) CallRemote(ctx context.Context, runtimeID signature.PublicKey, data []byte) ([]byte, error) {
	if c.client == nil {
		return nil, fmt.Errorf("keymanager/client: not configured")
	}

	// TODO: Call the correct key manager.
	return c.client.CallEnclave(ctx, data)
}

// New creates a new key manager client instance.
func New() (*Client, error) {
	keyManagerAddress := viper.GetString(cfgClientAddress)
	if keyManagerAddress == "" {
		// Presumably the key manager client is disabled.
		return &Client{nil}, nil
	}

	keyManagerCert := viper.GetString(cfgClientCert)

	client, err := enclaverpc.NewClient(keyManagerAddress, keyManagerCert, "key-manager")
	if err != nil {
		return nil, errors.Wrap(err, "keymanager/client: failed to create client")
	}

	return &Client{client}, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgClientAddress, "", "Key manager address")
		cmd.Flags().String(cfgClientCert, "", "Key manager TLS certificate")
	}

	for _, v := range []string{
		cfgClientAddress,
		cfgClientCert,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
