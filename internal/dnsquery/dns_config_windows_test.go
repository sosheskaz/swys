package dnsquery

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestDNSServersFromAdaptersSelectsUpAdapterServers(t *testing.T) {
	t.Parallel()

	down := windowsTestAdapter(windows.IfOperStatusDown, windowsTestIPv4DNS(192, 0, 2, 9))
	first := windowsTestAdapter(windows.IfOperStatusUp,
		windowsTestIPv4DNS(192, 0, 2, 1),
		&windows.IpAdapterDnsServerAdapter{},
		windowsTestIPv6DNS([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 0x53}, 0),
	)
	second := windowsTestAdapter(windows.IfOperStatusUp,
		windowsTestIPv4DNS(192, 0, 2, 1),
		windowsTestIPv6DNS([16]byte{0xfe, 0x80, 15: 0x01}, 12),
	)
	down.Next = first
	first.Next = second

	assert.Equal(t,
		[]string{"192.0.2.1", "2001:db8::53", "fe80::1%12"},
		dnsServersFromAdapters(down),
		"down adapters and empty addresses are skipped, duplicates keep their first position, IPv6 zones are kept",
	)
}

func windowsTestAdapter(status uint32, servers ...*windows.IpAdapterDnsServerAdapter) *windows.IpAdapterAddresses {
	for i := len(servers) - 2; i >= 0; i-- {
		servers[i].Next = servers[i+1]
	}
	adapter := &windows.IpAdapterAddresses{OperStatus: status}
	if len(servers) > 0 {
		adapter.FirstDnsServerAddress = servers[0]
	}
	return adapter
}

func windowsTestIPv4DNS(a, b, c, d byte) *windows.IpAdapterDnsServerAdapter {
	raw := new(syscall.RawSockaddrAny)
	inet4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(raw))
	inet4.Family = syscall.AF_INET
	inet4.Addr = [4]byte{a, b, c, d}
	return &windows.IpAdapterDnsServerAdapter{
		Address: windows.SocketAddress{Sockaddr: raw, SockaddrLength: int32(unsafe.Sizeof(*inet4))},
	}
}

func windowsTestIPv6DNS(address [16]byte, zone uint32) *windows.IpAdapterDnsServerAdapter {
	raw := new(syscall.RawSockaddrAny)
	inet6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(raw))
	inet6.Family = syscall.AF_INET6
	inet6.Addr = address
	inet6.Scope_id = zone
	return &windows.IpAdapterDnsServerAdapter{
		Address: windows.SocketAddress{Sockaddr: raw, SockaddrLength: int32(unsafe.Sizeof(*inet6))},
	}
}
