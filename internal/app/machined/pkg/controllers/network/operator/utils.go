// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package operator provides common methods for operators.
package operator

import (
	"fmt"
	"net"
	"net/netip"
)

// ToUDPAddr combines the given net.IP and port to form a net.UDPAddr.
func ToUDPAddr(ip net.IP, port uint16) (*net.UDPAddr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("failed to parse %q as an IP address", ip)
	}

	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port)), nil
}
