// +build linux

package host

import dynlib "git.schwanenlied.me/yawning/dynlib.git"

func loadDynlibCache() (*dynlib.Cache, error) {
	return dynlib.LoadCache()
}
