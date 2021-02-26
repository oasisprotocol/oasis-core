package api

import "github.com/oasisprotocol/oasis-core/go/common/crypto/signature"

// RoundResults contains information about how a particular round was executed by the consensus
// layer.
type RoundResults struct {
	// Messages are the results of executing emitted runtime messages.
	Messages []*MessageEvent `json:"messages,omitempty"`

	// GoodComputeNodes are the public keys of compute nodes that positively contributed to the
	// round by replicating the computation correctly.
	GoodComputeNodes []signature.PublicKey `json:"good_compute_nodes,omitempty"`
	// BadComputeNodes are the public keys of compute nodes that negatively contributed to the round
	// by causing discrepancies.
	BadComputeNodes []signature.PublicKey `json:"bad_compute_nodes,omitempty"`
}
