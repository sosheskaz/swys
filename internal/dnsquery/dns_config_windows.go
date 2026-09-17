//go:build windows

// Package dnsquery resolves DNS queries across supported transports.
package dnsquery

import (
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configuredDNSServers() ([]string, error) {
	size := uint32(15000)
	for range 3 {
		b := make([]byte, size)
		a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
		requested := size
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, a, &requested)
		if err == windows.ERROR_BUFFER_OVERFLOW && requested > size {
			size = requested
			continue
		}
		if err != nil {
			return nil, err
		}
		servers := dnsServersFromAdapters(a)
		runtime.KeepAlive(b)
		return servers, nil
	}
	return nil, fmt.Errorf("adapter data kept growing beyond %d bytes", size)
}

func dnsServersFromAdapters(a *windows.IpAdapterAddresses) []string {
	seen := map[string]bool{}
	var out []string
	for ; a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for e := a.FirstDnsServerAddress; e != nil; e = e.Next {
			if s, ok := windowsDNSServer(e); ok && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func windowsDNSServer(e *windows.IpAdapterDnsServerAdapter) (string, bool) {
	if e.Address.Sockaddr == nil || e.Address.SockaddrLength == 0 {
		return "", false
	}
	s, err := e.Address.Sockaddr.Sockaddr()
	if err != nil {
		return "", false
	}
	switch a := s.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrFrom4(a.Addr).String(), true
	case *syscall.SockaddrInet6:
		ip := netip.AddrFrom16(a.Addr)
		if a.ZoneId != 0 {
			ip = ip.WithZone(strconv.FormatUint(uint64(a.ZoneId), 10))
		}
		return ip.String(), true
	}
	return "", false
}
