package sgx

import "github.com/oasisprotocol/oasis-core/go/common/persistent"

// GetPlatformManifest retrieves the platform manifest from the node's local persistent store.
func GetPlatformManifest(dataDir string) ([]byte, error) {
	commonStore, err := persistent.NewCommonStore(dataDir)
	if err != nil {
		return nil, err
	}
	defer commonStore.Close()

	store := commonStore.GetServiceStore(serviceStoreName)
	defer store.Close()

	var platformManifest []byte
	if err = store.GetCBOR(platformManifestKey, &platformManifest); err != nil {
		return nil, err
	}

	return platformManifest, nil
}

// PersistPlatformManifest persists the platform manifest to the node's local persistent store.
func PersistPlatformManifest(dataDir string, platformManifest []byte) error {
	commonStore, err := persistent.NewCommonStore(dataDir)
	if err != nil {
		return err
	}
	defer commonStore.Close()

	store := commonStore.GetServiceStore(serviceStoreName)
	defer store.Close()

	return store.PutCBOR(platformManifestKey, platformManifest)
}
