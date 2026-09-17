//go:build windows

package cmd

import (
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const initialAdapterAddressesBuffer = 15_000

func configuredDNSServers() ([]string, error) {
	size := uint32(initialAdapterAddressesBuffer)
	for range 3 {
		buffer := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		requested := size
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_INCLUDE_PREFIX,
			0,
			adapters,
			&requested,
		)
		if err == windows.ERROR_BUFFER_OVERFLOW && requested > size {
			size = requested
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("get adapter addresses: %w", err)
		}
		servers := dnsServersFromAdapters(adapters)
		runtime.KeepAlive(buffer)
		return servers, nil
	}
	return nil, fmt.Errorf("get adapter addresses: adapter data kept growing beyond %d bytes", size)
}

func dnsServersFromAdapters(adapters *windows.IpAdapterAddresses) []string {
	seen := make(map[string]bool)
	var servers []string
	for adapter := adapters; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for entry := adapter.FirstDnsServerAddress; entry != nil; entry = entry.Next {
			server, ok := windowsDNSServer(entry)
			if ok && !seen[server] {
				seen[server] = true
				servers = append(servers, server)
			}
		}
	}
	return servers
}

func windowsDNSServer(entry *windows.IpAdapterDnsServerAdapter) (string, bool) {
	if entry.Address.Sockaddr == nil || entry.Address.SockaddrLength == 0 {
		return "", false
	}
	sockaddr, err := entry.Address.Sockaddr.Sockaddr()
	if err != nil {
		return "", false
	}
	switch address := sockaddr.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrFrom4(address.Addr).String(), true
	case *syscall.SockaddrInet6:
		ip := netip.AddrFrom16(address.Addr)
		if address.ZoneId != 0 {
			ip = ip.WithZone(strconv.FormatUint(uint64(address.ZoneId), 10))
		}
		return ip.String(), true
	default:
		return "", false
	}
}
