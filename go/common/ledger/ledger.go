// Packaged ledger contains the common constants and functions related to Ledger devices
package ledger

import (
	ledger "github.com/zondax/ledger-oasis-go"
)

const (
	// PathPurposeBIP44 is set to 44 to indicate the use of the BIP-0044's hierarchy:
	// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki.
	PathPurposeBIP44 uint32 = 44
	// PathPurposeOther is set to 43 to indicate the use of (proposed)
	// BIP-0043's extension that specifies the purpose for non-Bitcoin uses:
	// https://github.com/bitcoin/bips/pull/523/files
	PathPurposeOther uint32 = 43

	// PathSubPurposeConsensus is set to 0 to indicate it is to be used for
	// consensus-related things.
	PathSubPurposeConsensus uint32 = 0

	// ListingPathCoinType is set to 474, the index registered to Oasis in the SLIP-0044 registry.
	ListingPathCoinType uint32 = 474
	// ListingPathAccount is the account index used to list and connect to Ledger devices by address.
	ListingPathAccount uint32 = 0
	// ListingPathChange indicates an external chain.
	ListingPathChange uint32 = 0
	// ListingPathIndex is the address index used to list and connect to Ledger devices by address.
	ListingPathIndex uint32 = 0
)

// ListingDerivationPath is the path used to list and connect to devices by address.
var ListingDerivationPath = []uint32{
	PathPurposeBIP44, ListingPathCoinType, ListingPathAccount, ListingPathChange, ListingPathIndex,
}

// Device is a Ledger device.
type Device = ledger.LedgerOasis

// ListDevices will list Ledger devices by address, derived from ListingDerivationPath.
func ListDevices() {
	ledger.ListOasisDevices(ListingDerivationPath)
}

// ConnectToDevice attempts to connect to a Ledger device by address, which is derived by ListingDerivationPath.
func ConnectToDevice(address string, derivationPath []uint32) (*Device, error) {
	return ledger.ConnectLedgerOasisApp(address, derivationPath)
}
