// +build linux

package host

import dynlib "gitlab.com/yawning/dynlib.git"

func loadDynlibCache() (*dynlib.Cache, error) {
	return dynlib.LoadCache()
}
