package registry

import (
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
)

const (
	// AppID is the unique application identifier.
	AppID uint8 = 0x01

	// AppName is the ABCI application name.
	AppName string = "200_registry"
)

var (
	// EventType is the ABCI event type for registry events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by
	// the registry application.
	QueryApp = api.QueryForApp(AppName)

	// KeyRuntimeRegistered is the ABCI event attribute for new
	// runtime registrations (value is the CBOR serialized runtime
	// descriptor).
	KeyRuntimeRegistered = []byte("runtime.registered")

	// KeyEntityRegistered is the ABCI event attribute for new entity
	// registrations (value is the CBOR serialized entity descriptor).
	KeyEntityRegistered = []byte("entity.registered")

	// KeyEntityDeregistered is the ABCI event attribute for entity
	// deregistrations (value is a CBOR serialized EntityDeregistration).
	KeyEntityDeregistered = []byte("entity.deregistered")

	// KeyNodeRegistered is the ABCI event attribute for new node
	// registrations (value is the CBOR serialized node descriptor).
	KeyNodeRegistered = []byte("nodes.registered")

	// KeyNodesExpired is the ABCI event attribute for node
	// deregistrations due to expiration (value is a CBOR serialized
	// vector of node descriptors).
	KeyNodesExpired = []byte("nodes.expired")

	// KeyNodeUnfrozen is the ABCI event attribute for when nodes
	// become unfrozen (value is CBOR serialized node ID).
	KeyNodeUnfrozen = []byte("nodes.unfrozen")

	// KeyRegistryNodeListEpoch is the ABCI event attribute for
	// registry epochs.
	KeyRegistryNodeListEpoch = []byte("nodes.epoch")
)

// EntityDeregistration is an entity deregistration.
type EntityDeregistration struct {
	// Deregistered entity.
	Entity entity.Entity `json:"entity"`
}
