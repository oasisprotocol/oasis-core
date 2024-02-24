package interop

import (
	"context"

	churpInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state/interop"
	secretsInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state/interop"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

func InitializeTestKeyManagerState(ctx context.Context, mkvs mkvs.Tree) error {
	if err := secretsInterop.InitializeTestKeyManagerSecretsState(ctx, mkvs); err != nil {
		return err
	}
	return churpInterop.InitializeTestKeyManagerSecretsState(ctx, mkvs)
}
