package host

import "git.schwanenlied.me/yawning/dynlib.git"

func loadCache() (dynlib.Cache, error) {
	return dynlib.LoadCache()
}
