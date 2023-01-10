package protocol

import (
	"github.com/oasisprotocol/oasis-core/go/common/errors"
)

// ModuleVerifierName is the name of the consensus verifier module inside the runtime.
const ModuleVerifierName = "verifier"

// ErrVerifierVerificationFailed is the error returned when consensus verifier fails to verify the
// passed consensus light block.
var ErrVerifierVerificationFailed = errors.New(ModuleVerifierName, 2, "verifier: light block verification failed")
