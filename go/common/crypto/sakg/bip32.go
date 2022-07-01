package sakg

import (
	"fmt"
	"strconv"
	"strings"
)

// HardenedKeysIndexStart is the index of the first hardened BIP-0032 key.
const HardenedKeysIndexStart = uint32(0x80000000)

const (
	// BIP32PathMnemonicComponent is the string representing the mnemonic
	// (first) component of a BIP-0032 path.
	BIP32PathMnemonicComponent = "m"
	// BIP32HardenedComponentSuffix is the string representing the suffix of a
	// hardened component of a BIP-00032 path.
	BIP32HardenedComponentSuffix = "'"
)

// BIP32Path represents a BIP-0032 path.
type BIP32Path []uint32

// String returns the string representation of a BIP-0032 path.
//
// NOTE: Hardened paths are marked with BIP32HardenedComponentSuffix.
func (path BIP32Path) String() string {
	compStrs := make([]string, 0, len(path)+1)

	compStrs = append(compStrs, BIP32PathMnemonicComponent)
	for _, component := range path {
		var suffix string
		if component >= HardenedKeysIndexStart {
			component -= HardenedKeysIndexStart
			suffix = BIP32HardenedComponentSuffix
		}

		compStr := fmt.Sprintf("%d%s", component, suffix)
		compStrs = append(compStrs, compStr)
	}

	return strings.Join(compStrs, "/")
}

// MarshalText encodes a BIP-0032 path into text form.
func (path BIP32Path) MarshalText() ([]byte, error) {
	return []byte(path.String()), nil
}

// UnmarshalText decodes a text marshaled BIP-0032 path.
func (path *BIP32Path) UnmarshalText(text []byte) error {
	components := strings.Split(string(text), "/")
	// NOTE: The first component should be the mnemonic component which doesn't
	// have a corresponding element in BIP32Path's slice.
	n := len(components) - 1

	rawPath := make([]uint32, 0, n)

	if components[0] != BIP32PathMnemonicComponent {
		return fmt.Errorf(
			"invalid BIP-0032 path's mnemonic component: %s (expected: %s)",
			components[0],
			BIP32PathMnemonicComponent,
		)
	}

	if len(components) > 1 {
		for i, component := range components[1:] {
			// Use 1-based component indexing. First component is the mnemonic.
			componentIndex := i + 2

			hardened := strings.HasSuffix(component, BIP32HardenedComponentSuffix)
			if hardened {
				component = strings.TrimSuffix(component, BIP32HardenedComponentSuffix)
			}
			comp64, err := strconv.ParseUint(component, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid BIP-0032 path's %d. component: %w",
					componentIndex,
					err,
				)
			}
			comp32 := uint32(comp64)
			if comp32 >= HardenedKeysIndexStart {
				return fmt.Errorf(
					"invalid BIP-0032 path's %d. component: maximum value of %d exceeded (got: %d)",
					componentIndex,
					HardenedKeysIndexStart-1,
					comp32,
				)
			}
			if hardened {
				comp32 |= HardenedKeysIndexStart
			}
			rawPath = append(rawPath, comp32)
		}
	}

	*path = BIP32Path(rawPath)
	return nil
}

// NewBIP32Path creates a BIP32Path object from the given BIP-0032 path's string
// representation.
func NewBIP32Path(pathStr string) (BIP32Path, error) {
	var path BIP32Path
	if err := path.UnmarshalText([]byte(pathStr)); err != nil {
		return nil, err
	}
	return path, nil
}
