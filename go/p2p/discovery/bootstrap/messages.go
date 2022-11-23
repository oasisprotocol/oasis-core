package bootstrap

import (
	"time"
)

// AdvertiseRequest is a message requesting seed to register the peer.
type AdvertiseRequest struct {
	Namespace string `json:"namespace,omitempty"`
}

// AdvertiseResponse is a message response with a deadline for the next registration.
type AdvertiseResponse struct {
	TTL time.Duration `json:"ttl,omitempty"`
}

// DiscoverRequest is a message requesting peers.
type DiscoverRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// DiscoverResponse is a message response with a list of json encoded peer addresses.
type DiscoverResponse struct {
	Peers [][]byte `json:"peers,omitempty"`
}
