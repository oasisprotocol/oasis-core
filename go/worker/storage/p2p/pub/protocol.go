package pub

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// StoragePubProtocolID is a unique protocol identifier for the storage pub protocol.
const StoragePubProtocolID = "storagepub"

// StoragePubProtocolVersion is the supported version of the storage pub protocol.
var StoragePubProtocolVersion = version.Version{Major: 1, Minor: 0, Patch: 0}

// Constants related to the Get method.
const (
	MethodGet          = "Get"
	MaxGetResponseTime = 5 * time.Second
)

// GetRequest is a Get request.
type GetRequest = syncer.GetRequest

// ProofResponse is a response to Get/GetPrefixes/Iterate containing a proof.
type ProofResponse = syncer.ProofResponse

// Constants related to the GetPrefixes method.
const (
	MethodGetPrefixes          = "GetPrefixes"
	MaxGetPrefixesResponseTime = 5 * time.Second
)

// GetPrefixesRequest is a GetPrefixes request.
type GetPrefixesRequest = syncer.GetPrefixesRequest

// Constants related to the Iterate method.
const (
	MethodIterate          = "Iterate"
	MaxIterateResponseTime = 5 * time.Second
)

// IterateRequest is an Iterate request.
type IterateRequest = syncer.IterateRequest
