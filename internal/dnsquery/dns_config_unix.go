//go:build !windows

// Package dnsquery resolves DNS queries across supported transports.
package dnsquery

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func configuredDNSServers() ([]string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("open /etc/resolv.conf: %w", err)
	}
	servers, parseErr := parseConfiguredDNSServers(f)
	return servers, errors.Join(parseErr, f.Close())
}

func parseConfiguredDNSServers(input io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(input)
	var servers []string
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			servers = append(servers, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan /etc/resolv.conf: %w", err)
	}
	return servers, nil
}
