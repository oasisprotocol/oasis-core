package api

import "github.com/oasisprotocol/oasis-core/go/common/crypto/signature"

// RoundResults contains information about how a particular round was executed by the consensus
// layer.
type RoundResults struct {
	// Messages are the results of executing emitted runtime messages.
	Messages []*MessageEvent `json:"messages,omitempty"`

	// GoodComputeEntities are the public keys of compute nodes' controlling entities that
	// positively contributed to the round by replicating the computation correctly.
	GoodComputeEntities []signature.PublicKey `json:"good_compute_entities,omitempty"`
	// BadComputeEntities are the public keys of compute nodes' controlling entities that
	// negatively contributed to the round by causing discrepancies.
	BadComputeEntities []signature.PublicKey `json:"bad_compute_entities,omitempty"`
}
