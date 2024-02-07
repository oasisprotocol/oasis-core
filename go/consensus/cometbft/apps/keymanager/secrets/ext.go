package secrets

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

// Ensure that the master and ephemeral secrets extension implements the Extension interface.
var _ tmapi.Extension = (*secretsExt)(nil)

type secretsExt struct {
	appName string
	state   tmapi.ApplicationState
}

// New creates a new master and ephemeral secrets extension for the key manager application.
func New(appName string) tmapi.Extension {
	return &secretsExt{
		appName: appName,
	}
}

// Methods implements api.Extension.
func (ext *secretsExt) Methods() []transaction.MethodName {
	return secrets.Methods
}

// OnRegister implements api.Extension.
func (ext *secretsExt) OnRegister(state tmapi.ApplicationState, _ tmapi.MessageDispatcher) {
	ext.state = state
}

// ExecuteTx implements api.Extension.
func (ext *secretsExt) ExecuteTx(ctx *tmapi.Context, tx *transaction.Transaction) error {
	state := secretsState.NewMutableState(ctx.State())

	switch tx.Method {
	case secrets.MethodUpdatePolicy:
		var sigPol secrets.SignedPolicySGX
		if err := cbor.Unmarshal(tx.Body, &sigPol); err != nil {
			return secrets.ErrInvalidArgument
		}
		return ext.updatePolicy(ctx, state, &sigPol)
	case secrets.MethodPublishMasterSecret:
		var sigSec secrets.SignedEncryptedMasterSecret
		if err := cbor.Unmarshal(tx.Body, &sigSec); err != nil {
			return secrets.ErrInvalidArgument
		}
		return ext.publishMasterSecret(ctx, state, &sigSec)
	case secrets.MethodPublishEphemeralSecret:
		var sigSec secrets.SignedEncryptedEphemeralSecret
		if err := cbor.Unmarshal(tx.Body, &sigSec); err != nil {
			return secrets.ErrInvalidArgument
		}
		return ext.publishEphemeralSecret(ctx, state, &sigSec)
	default:
		panic(fmt.Sprintf("keymanager: secrets: invalid method: %s", tx.Method))
	}
}

// BeginBlock implements api.Extension.
func (ext *secretsExt) BeginBlock(ctx *tmapi.Context) error {
	changed, epoch := ext.state.EpochChanged(ctx)
	if !changed {
		return nil
	}

	return ext.onEpochChange(ctx, epoch)
}

// EndBlock implements api.Extension.
func (ext *secretsExt) EndBlock(*tmapi.Context) error {
	return nil
}
