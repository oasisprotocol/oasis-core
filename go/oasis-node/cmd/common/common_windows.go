//go:build windows

package common

func initRlimit() error {
	return nil
}

func Umask(int) int {
	return 0
}
