// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.rbl

package operators

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const timeout = 500 * time.Millisecond

// Description:
// Looks up the input IP address in the specified RBL (Real-time Block List) service.
// Performs DNS lookups to check if the IP is listed. Sets TX.httpbl_msg variable with
// the response text if found. Has a 500ms timeout for DNS queries.
//
// Arguments:
// RBL hostname to query (e.g., "sbl-xbl.spamhaus.org").
//
// Returns:
// true if the IP address is found in the RBL, false otherwise or on timeout
//
// Example:
// ```
// # Check IP against Spamhaus blocklist
// SecRule REMOTE_ADDR "@rbl sbl-xbl.spamhaus.org" "id:183,deny,log,msg:'IP found in RBL'"
//
// # Multiple RBL checks
// SecRule REMOTE_ADDR "@rbl dnsbl.example.com" "id:184,deny"
// ```
type rbl struct {
	service  string
	resolver *net.Resolver
}

var _ plugintypes.Operator = (*rbl)(nil)

func newRBL(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	data := options.Arguments
	if data == "" {
		// Without a zone every lookup goes to the DNS root and no address can
		// ever be listed, so the rule would load as enforcement that is inert.
		return nil, errors.New("missing RBL service hostname")
	}

	return &rbl{
		service:  data,
		resolver: net.DefaultResolver,
	}, nil
}

// https://github.com/mrichman/godnsbl
// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
func (o *rbl) Evaluate(tx plugintypes.TransactionState, ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		// The operand is unvalidated request data, so it stays out of the message.
		tx.DebugLogger().Warn().Msg("RBL lookup skipped: operand is not an IP address")
		return false
	}

	// The lookups take the deadline through the context, so they unwind on
	// their own and no work outlives Evaluate.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addr := rblQueryName(ip, o.service)
	// LookupIP and LookupNetIP would undo that: they go through the shared
	// lookup group in net, where concurrent lookups of one name join a single
	// call that stops being cancellable as soon as it has a second waiter and
	// then outlives all of them, so a slow blocklist would pin a goroutine per
	// request.
	res, err := o.resolver.LookupHost(ctx, addr)
	if err != nil {
		logRBLLookupError(tx, addr, err)
		return false
	}
	if !anyListingCode(res) {
		tx.DebugLogger().Warn().
			Str("address", addr).
			Str("answers", strings.Join(res, " ")).
			Msg("RBL answer is not a listing code, treating IP as not listed")
		return false
	}

	// The address record alone decides that the IP is listed. The TXT record
	// only carries the human-readable reason, so a zone that publishes none —
	// or a TXT lookup that fails on its own — must not undo the verdict.
	var reason string
	if txt, err := o.resolver.LookupTXT(ctx, addr); err != nil {
		// The address lookup that just succeeded proves the resolver answers,
		// so a failure here is almost always a zone with no TXT record, and it
		// costs nothing: the verdict is already settled.
		tx.DebugLogger().Debug().Err(err).Str("address", addr).Msg("RBL reason lookup failed")
	} else if len(txt) > 0 {
		reason = txt[0]
	}
	// Whatever the reason turns out to be, it has to describe this match: a
	// zone that publishes no TXT record must not leave an earlier RBL rule's
	// message standing as if it belonged here.
	if reason == "" {
		tx.Variables().TX().Remove("httpbl_msg")
	} else {
		tx.Variables().TX().Set("httpbl_msg", []string{reason})
	}
	tx.CaptureField(0, reason)
	return true
}

// anyListingCode reports whether an answer means the address asked about is
// listed. RFC 5782 §2.1 puts a listing in 127.0.0.0/8, and zones answer in the
// top of that block, 127.255.255.0/24, to complain about the query itself — a
// public resolver, an exhausted quota — which says nothing about the address.
// A resolver that invents an address for every name it cannot resolve answers
// outside 127.0.0.0/8 altogether. Reading either as a listing would block
// every request.
func anyListingCode(answers []string) bool {
	for _, answer := range answers {
		v4 := net.ParseIP(answer).To4()
		if v4 != nil && v4[0] == 127 && (v4[1] != 255 || v4[2] != 255) {
			return true
		}
	}
	return false
}

// rblQueryName builds the name to look up for ip in the blocklist zone, the
// address written backwards in front of the zone: IPv4 as reversed decimal
// octets (1.2.3.4 in example.com becomes 4.3.2.1.example.com) and IPv6 as
// reversed hex nibbles, per RFC 5782 §2.1 and §2.4. An IPv4-mapped IPv6
// address takes the IPv4 form, which is what its zone entry uses.
func rblQueryName(ip net.IP, zone string) string {
	var name strings.Builder
	if v4 := ip.To4(); v4 != nil {
		for i := len(v4) - 1; i >= 0; i-- {
			name.WriteString(strconv.Itoa(int(v4[i])))
			name.WriteByte('.')
		}
	} else {
		nibbles := hex.EncodeToString(ip.To16())
		for i := len(nibbles) - 1; i >= 0; i-- {
			name.WriteByte(nibbles[i])
			name.WriteByte('.')
		}
	}
	name.WriteString(zone)
	return name.String()
}

// logRBLLookupError reports a failed lookup at the level its cause deserves. A
// missing record is the ordinary negative answer, a timeout is the service
// being slow, and a cancelled lookup is the caller giving up, so none of them
// is logged as an engine error: an unreachable or slow RBL would otherwise
// write one error line per request.
func logRBLLookupError(tx plugintypes.TransactionState, addr string, err error) {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		tx.DebugLogger().Debug().Str("address", addr).Msg("RBL record not found")
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		tx.DebugLogger().Warn().Str("address", addr).Msg("RBL lookup timed out, treating IP as not listed")
	case errors.Is(err, context.Canceled):
		tx.DebugLogger().Debug().Str("address", addr).Msg("RBL lookup cancelled")
	default:
		tx.DebugLogger().Error().Err(err).Str("address", addr).Msg("RBL DNS lookup failed")
	}
}

func init() {
	Register("rbl", newRBL)
}
