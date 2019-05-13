package host

import "errors"

type FilterFunc func(string) error

type Cache struct{}

func (Cache) ResolveLibraries(binaries []string, extraLibs []string, ldLibraryPath, fallbackSearchPath string, filterFn FilterFunc) (map[string][]string, error) {
	return nil, errors.New("ResolveLibraries not implemented for darwin")
}

func loadCache() (*Cache, error) {
	return nil, errors.New("darwin does not implement dynlib")
}
