// Packaged ledger contains the common constants and functions related to Ledger devices
package ledger

import (
	ledger "github.com/zondax/ledger-oasis-go"
)

const (
	// ListingPathPurpose is set to 44 to indicate use of the BIP-0044 specification.
	ListingPathPurpose uint32 = 44
	// ListingPathCoinType is set to 118, the number owned by Cosmos via SLIP-0044 registration.
	// TODO: Update this number after SLIP-0044 registration is complete.
	ListingPathCoinType uint32 = 118
	// ListingPathAccount is the account index used to list and connect to Ledger devices by address.
	ListingPathAccount uint32 = 0
	// ListingPathChange indicates an external chain.
	ListingPathChange uint32 = 0
	// ListingPathIndex is the address index used to list and connect to Ledger devices by address.
	ListingPathIndex uint32 = 0
)

var (
	// ListingDerivationPath is the path used to list and connect to devices by address.
	ListingDerivationPath = []uint32{ListingPathPurpose, ListingPathCoinType, ListingPathAccount, ListingPathChange, ListingPathIndex}
)

// Device is to clean up imports of ledger-oasis-go.
type Device = ledger.LedgerOasis

// ListDevices will list Ledger devices by address, derived from ListingDerivationPath.
func ListDevices() {
	ledger.ListOasisDevices(ListingDerivationPath)
}

// ConnectToDevice attempts to connect to a Ledger device by address, which is derived by ListingDerivationPath.
func ConnectToDevice(address string) (*Device, error) {
	return ledger.ConnectLedgerOasisApp(address, ListingDerivationPath)
}
