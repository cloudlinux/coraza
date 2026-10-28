// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !coraza.disabled_operators.ipMatch

package operators

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// Description:
// Performs fast IPv4 or IPv6 address matching with support for CIDR notation.
// Can match individual IPs or IP ranges. Automatically adds appropriate subnet masks
// (/32 for IPv4, /128 for IPv6) when not specified.
//
// Arguments:
// Comma-separated list of IP addresses with optional CIDR blocks (e.g., "192.168.1.0/24, 10.0.0.1").
//
// Returns:
// true if the input IP address matches any of the provided IPs or ranges, false otherwise
//
// Example:
// ```seclang
// # Block specific IPs and ranges
// SecRule REMOTE_ADDR "@ipMatch 192.168.1.100,192.168.1.50,10.10.50.0/24" "id:160,deny,log"
//
// # Allow internal network
// SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8,172.16.0.0/12" "id:161,pass"
// ```
type ipMatch struct {
	// prefixes holds every network, masked. v4Bits and v6Bits list the distinct
	// prefix lengths per family, so a lookup is one map probe per length.
	prefixes       map[netip.Prefix]struct{}
	v4Bits, v6Bits []int
}

var _ plugintypes.Operator = (*ipMatch)(nil)

func newIPMatch(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments

	o := &ipMatch{prefixes: map[netip.Prefix]struct{}{}}
	for _, sb := range strings.Split(data, ",") {
		sb = strings.TrimSpace(sb)
		if sb == "" {
			continue
		}
		if strings.Contains(sb, ":") && !strings.Contains(sb, "/") {
			// ipv6
			sb += "/128"
		} else if strings.Contains(sb, ".") && !strings.Contains(sb, "/") {
			// ipv4
			sb += "/32"
		}
		_, subnet, err := net.ParseCIDR(sb)
		if err != nil {
			continue
		}
		addr, _ := netip.AddrFromSlice(subnet.IP)
		ones, _ := subnet.Mask.Size()
		if addr.Is4In6() {
			// IPNet.Contains treats an IPv4-mapped network as IPv4.
			addr, ones = addr.Unmap(), ones-96
		}
		o.prefixes[netip.PrefixFrom(addr, ones)] = struct{}{}
		if addr.Is4() {
			if !slices.Contains(o.v4Bits, ones) {
				o.v4Bits = append(o.v4Bits, ones)
			}
		} else if !slices.Contains(o.v6Bits, ones) {
			o.v6Bits = append(o.v6Bits, ones)
		}
	}
	return o, nil
}

func (o *ipMatch) Evaluate(tx plugintypes.TransactionState, value string) bool {
	ip, err := netip.ParseAddr(value)
	// net.ParseIP, which the networks are parsed with, rejects zones.
	if err != nil || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	bits := o.v6Bits
	if ip.Is4() {
		bits = o.v4Bits
	}
	for _, b := range bits {
		p, _ := ip.Prefix(b)
		if _, ok := o.prefixes[p]; ok {
			return true
		}
	}
	return false
}

func init() {
	Register("ipMatch", newIPMatch)
}
