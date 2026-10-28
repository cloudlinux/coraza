// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

func TestIPMatch(t *testing.T) {
	tests := []struct {
		name  string
		rules string
		input string
		want  bool
	}{
		{"single address", "127.0.0.1/32", "127.0.0.1", true},
		{"single address, other ip", "127.0.0.1/32", "127.0.0.2", false},
		{"bare ipv4 is /32", "127.0.0.1, 192.168.0.0/24", "127.0.0.1", true},
		{"bare ipv4 is /32, neighbour", "127.0.0.1, 192.168.0.0/24", "127.0.0.2", false},
		{"ipv4 range", "127.0.0.1, 192.168.0.0/24", "192.168.0.253", true},
		{"ipv4 range, outside", "127.0.0.1, 192.168.0.0/24", "192.168.1.1", false},
		{"host bits are masked", "10.1.2.3/8", "10.200.0.1", true},
		{"ipv4 /0 matches any ipv4", "0.0.0.0/0", "8.8.8.8", true},
		{"ipv4 /0 does not match ipv6", "0.0.0.0/0", "2001:db8::1", false},
		{"bare ipv6 is /128", "2001:db8::1", "2001:db8::1", true},
		{"bare ipv6 is /128, neighbour", "2001:db8::1", "2001:db8::2", false},
		{"ipv6 range", "2001:db8::/32", "2001:db8:ffff::1", true},
		{"ipv6 range, outside", "2001:db8::/32", "2001:db9::1", false},
		{"ipv4-mapped input matches ipv4 range", "192.168.0.0/16", "::ffff:192.168.1.1", true},
		{"ipv4-mapped range is an ipv4 range", "::ffff:192.168.0.0/112", "192.168.1.1", true},
		{"ipv4-mapped range is an ipv4 range, outside", "::ffff:192.168.0.0/112", "192.169.1.1", false},
		{"ipv4-mapped /96 matches any ipv4", "::ffff:0:0/96", "8.8.8.8", true},
		{"ipv4-mapped /96 does not match ipv6", "::ffff:0:0/96", "::1", false},
		{"short ipv4-mapped range, ipv4 input", "::ffff:0:0/80", "192.168.1.1", false},
		{"short ipv4-mapped range, ipv6 input", "::ffff:0:0/80", "::1", true},
		{"zoned input is not an ip", "fe80::/10", "fe80::1%eth0", false},
		{"invalid input", "0.0.0.0/0", "not-an-ip", false},
		{"empty input", "0.0.0.0/0", "", false},
		{"invalid entries are skipped", "bogus, 10.0.0.0/8", "10.1.1.1", true},
		{"overlapping ranges", "10.0.0.0/8, 10.1.0.0/16", "10.2.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipm, err := newIPMatch(plugintypes.OperatorOptions{Arguments: tt.rules})
			if err != nil {
				t.Fatal(err)
			}
			if got := ipm.Evaluate(nil, tt.input); got != tt.want {
				t.Errorf("@ipMatch %q on %q = %v, want %v", tt.rules, tt.input, got, tt.want)
			}
		})
	}
}
