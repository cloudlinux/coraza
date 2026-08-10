// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.rbl

package operators

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	return &rbl{
		service:  data,
		resolver: net.DefaultResolver,
	}, nil
}

// https://github.com/mrichman/godnsbl
// https://github.com/SpiderLabs/ModSecurity/blob/b66224853b4e9d30e0a44d16b29d5ed3842a6b11/src/operators/rbl.cc
func (o *rbl) Evaluate(tx plugintypes.TransactionState, ipAddr string) bool {
	if net.ParseIP(ipAddr) == nil {
		// The operand is unvalidated request data, so it stays out of the message.
		tx.DebugLogger().Warn().Msg("RBL lookup skipped: operand is not an IP address")
		return false
	}

	// The lookups take the deadline through the context, so they unwind on
	// their own and no work outlives Evaluate.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addr := fmt.Sprintf("%s.%s", ipAddr, o.service)
	res, err := o.resolver.LookupHost(ctx, addr)
	if err != nil {
		logRBLLookupError(tx, addr, err)
		return false
	}

	var status string
	if len(res) > 0 {
		txt, err := o.resolver.LookupTXT(ctx, addr)
		if err != nil {
			logRBLLookupError(tx, addr, err)
			return false
		}
		if len(txt) > 0 {
			status = txt[0]
		}
	}
	if status != "" {
		tx.Variables().TX().Set("httpbl_msg", []string{status})
		tx.CaptureField(0, status)
	}
	return true
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
