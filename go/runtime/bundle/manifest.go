package bundle

import (
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/version"
)

const (
	manifestPath = "META-INF"
	manifestName = manifestPath + "/MANIFEST.MF"
)

// Manifest is a deserialized runtime bundle manifest.
type Manifest struct {
	// Name is the optional human readable runtime name.
	Name string `json:"name,omitempty"`

	// ID is the runtime ID.
	ID common.Namespace `json:"id"`

	// Version is the runtime version.
	Version version.Version `json:"version,omitempty"`

	// Executable is the name of the runtime ELF executable file.
	Executable string `json:"executable"`

	// SGX is the SGX specific manifest metadata if any.
	SGX *SGXMetadata `json:"sgx,omitempty"`

	// Digests is the cryptographic digests of the bundle contents,
	// excluding the manifest.
	Digests map[string]hash.Hash `json:"digests"`
}

// SGXMetadata is the SGX specific manifest metadata.
type SGXMetadata struct {
	// Executable is the name of the SGX enclave executable file.
	Executable string `json:"executable"`

	// Signature is the name of the SGX enclave signature file.
	Signature string `json:"signature"`
}
