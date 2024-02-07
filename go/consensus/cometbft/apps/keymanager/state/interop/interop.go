package interop

import (
	"context"

	secretsInterop "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state/interop"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

func InitializeTestKeyManagerState(ctx context.Context, mkvs mkvs.Tree) error {
	return secretsInterop.InitializeTestKeyManagerSecretsState(ctx, mkvs)
}
