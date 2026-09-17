//go:build !windows

package cmd

import (
	"errors"
	"fmt"
	"os"
)

func configuredDNSServers() ([]string, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("open /etc/resolv.conf: %w", err)
	}
	servers, parseErr := parseConfiguredDNSServers(file)
	return servers, errors.Join(parseErr, file.Close())
}
