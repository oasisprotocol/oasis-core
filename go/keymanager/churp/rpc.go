package churp

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

var (
	// RPCMethodInit is the name of the `init` method.
	RPCMethodInit = "churp/init"

	// RPCMethodShareReduction is the name of the `share_reduction` method.
	RPCMethodShareReduction = "churp/share_reduction"

	// RPCMethodShareDistribution is the name of the `share_distribution` method.
	RPCMethodShareDistribution = "churp/share_distribution"

	// RPCMethodProactivization is the name of the `proactivization` method.
	RPCMethodProactivization = "churp/proactivization"

	// RPCMethodConfirm is the name of the `confirm` method.
	RPCMethodConfirm = "churp/confirm"

	// RPCMethodFinalize is the name of the `finalize` method.
	RPCMethodFinalize = "churp/finalize"

	// RPCMethodVerificationMatrix is the name of the `verification_matrix` method.
	RPCMethodVerificationMatrix = "churp/verification_matrix"

	// RPCMethodShareReductionPoint is the name of the `share_reduction_point` method.
	RPCMethodShareReductionPoint = "churp/share_reduction_point"

	// RPCMethodShareDistributionPoint is the name of the `share_distribution_point` method.
	RPCMethodShareDistributionPoint = "churp/share_distribution_point"

	// RPCMethodBivariateShare is the name of the `bivariate_share` method.
	RPCMethodBivariateShare = "churp/bivariate_share"
)

// HandoffRequest represents a handoff request.
type HandoffRequest struct {
	Identity

	// Epoch is the epoch of the handoff.
	Epoch beacon.EpochTime `json:"epoch,omitempty"`
}

// FetchRequest is a fetch handoff data request.
type FetchRequest struct {
	Identity

	// Epoch is the epoch of the handoff.
	Epoch beacon.EpochTime `json:"epoch,omitempty"`

	// NodeIDs contains the public keys of nodes from which to fetch data.
	NodeIDs []signature.PublicKey `json:"node_ids"`
}

// FetchResponse is a fetch handoff data response.
type FetchResponse struct {
	// Completed indicates whether the data fetching was completed.
	Completed bool `json:"completed,omitempty"`

	// Succeeded contains the public keys of nodes from which data was
	// successfully fetched.
	Succeeded []signature.PublicKey `json:"succeeded,omitempty"`

	// Failed contains the public keys of nodes from which data failed
	// to be fetched.
	Failed []signature.PublicKey `json:"failed,omitempty"`
}
