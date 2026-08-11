// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo && !coraza.disabled_operators.rbl

package operators

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/foxcpp/go-mockdns"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
)

type testLogger struct{ t *testing.T }

func (l *testLogger) Printf(format string, v ...any) {
	l.t.Helper()
	l.t.Logf(format, v...)
}

func TestRbl(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "xbl.spamhaus.org",
	}
	op, err := newRBL(opts)
	if err != nil {
		t.Fatal("Cannot init rbl operator")
	}

	logger := &testLogger{t}

	// Zone entries carry the reversed names a blocklist actually publishes:
	// 1.2.3.4 is listed as 4.3.2.1.<zone>. The names differ from the plain
	// addresses, so a lookup built the wrong way round misses them.
	srv, err := mockdns.NewServerWithLogger(map[string]mockdns.Zone{
		"4.3.2.1.xbl.spamhaus.org.": {
			A:   []string{"127.0.0.2"},
			TXT: []string{"blocked"},
		},
		"5.3.2.1.xbl.spamhaus.org.": {
			A: []string{"127.0.0.2"},
		},
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.xbl.spamhaus.org.": {
			A:   []string{"127.0.0.2"},
			TXT: []string{"blocked v6"},
		},
		// Only the unreversed name of 1.2.3.6 exists, so the operator must
		// find nothing for it.
		"1.2.3.6.xbl.spamhaus.org.": {
			A:   []string{"127.0.0.2"},
			TXT: []string{"unreversed"},
		},
		// 3.4.5.6 gets the answer a resolver that invents addresses for names
		// it cannot resolve would give, and 4.4.5.6 the code a zone answers
		// with when it objects to the query rather than the address.
		"6.5.4.3.xbl.spamhaus.org.": {
			A: []string{"203.0.113.9"},
		},
		"6.5.4.4.xbl.spamhaus.org.": {
			A: []string{"127.255.255.254"},
		},
	}, logger, false)
	if err != nil {
		t.Fatalf("Cannot start mockdns server: %v", err)
	}
	defer srv.Close()

	srv.PatchNet(op.(*rbl).resolver)
	defer mockdns.UnpatchNet(op.(*rbl).resolver)

	t.Run("Listed IP with TXT record", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "1.2.3.4") {
			t.Fatal("Unexpected result for listed IP")
		}
		if want, have := "blocked", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for listed IP: want %q, have %q", want, have)
		}
	})

	t.Run("Listed IP without TXT record", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "1.2.3.5") {
			t.Error("a listed IP whose zone publishes no TXT record must still be reported listed")
		}
		if got := tx.Variables().TX().Get("httpbl_msg"); len(got) > 0 {
			t.Errorf("httpbl_msg set without a TXT record: %q", got)
		}
	})

	t.Run("Listed IPv6", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "2001:db8::1") {
			t.Fatal("Unexpected result for listed IPv6 address")
		}
		if want, have := "blocked v6", tx.Variables().TX().Get("httpbl_msg")[0]; want != have {
			t.Errorf("Unexpected result for listed IPv6 address: want %q, have %q", want, have)
		}
	})

	t.Run("Unlisted IP", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if op.Evaluate(tx, "127.0.0.2") {
			t.Errorf("Unexpected result for unlisted IP")
		}
		if got := tx.Variables().TX().Get("httpbl_msg"); len(got) > 0 {
			t.Errorf("httpbl_msg set for unlisted IP: %q", got)
		}
	})

	t.Run("IP listed only under its unreversed name", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if op.Evaluate(tx, "1.2.3.6") {
			t.Error("the operator queried the unreversed name")
		}
	})

	t.Run("Answer outside the listing range", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if op.Evaluate(tx, "3.4.5.6") {
			t.Error("an answer outside 127.0.0.0/8 must not be read as a listing")
		}
	})

	t.Run("Answer complaining about the query", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if op.Evaluate(tx, "4.4.5.6") {
			t.Error("an answer in 127.255.255.0/24 must not be read as a listing")
		}
	})

	t.Run("Reason of an earlier match does not survive", func(t *testing.T) {
		tx := corazawaf.NewWAF().NewTransaction()
		if !op.Evaluate(tx, "1.2.3.4") {
			t.Fatal("Unexpected result for listed IP")
		}
		if !op.Evaluate(tx, "1.2.3.5") {
			t.Fatal("Unexpected result for listed IP without a TXT record")
		}
		if got := tx.Variables().TX().Get("httpbl_msg"); len(got) > 0 {
			t.Errorf("httpbl_msg still holds the earlier match's reason: %q", got)
		}
	})
}

func TestRblRequiresAService(t *testing.T) {
	if _, err := newRBL(plugintypes.OperatorOptions{}); err == nil {
		t.Error("an @rbl rule with no service hostname must not load")
	}
}

func TestRblQueryName(t *testing.T) {
	tests := []struct{ ip, want string }{
		{"1.2.3.4", "4.3.2.1.example.com"},
		{"127.0.0.2", "2.0.0.127.example.com"},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.example.com"},
		{"::ffff:1.2.3.4", "4.3.2.1.example.com"},
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test fixture %q is not an IP address", tc.ip)
		}
		if have := rblQueryName(ip, "example.com"); have != tc.want {
			t.Errorf("rblQueryName(%q): want %q, have %q", tc.ip, tc.want, have)
		}
	}
}

// errorCapturingWAF returns a WAF whose debug logger records, at Error level
// only, every message that reaches the printer.
func errorCapturingWAF() (*corazawaf.WAF, func() []string) {
	var mu sync.Mutex
	var lines []string
	factory := func(io.Writer) debuglog.Printer {
		return func(_ debuglog.Level, message, fields string) {
			mu.Lock()
			defer mu.Unlock()
			lines = append(lines, message+" "+fields)
		}
	}
	waf := corazawaf.NewWAF()
	waf.Logger = debuglog.DefaultWithPrinterFactory(factory).WithLevel(debuglog.LevelError)
	return waf, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func TestRblUnlistedIPDoesNotLogError(t *testing.T) {
	opts := plugintypes.OperatorOptions{
		Arguments: "xbl.spamhaus.org",
	}
	op, err := newRBL(opts)
	if err != nil {
		t.Fatal("Cannot init rbl operator")
	}

	srv, err := mockdns.NewServerWithLogger(map[string]mockdns.Zone{}, &testLogger{t}, false)
	if err != nil {
		t.Fatalf("Cannot start mockdns server: %v", err)
	}
	defer srv.Close()
	srv.PatchNet(op.(*rbl).resolver)
	defer mockdns.UnpatchNet(op.(*rbl).resolver)

	waf, capturedErrors := errorCapturingWAF()
	tx := waf.NewTransaction()
	if op.Evaluate(tx, "127.0.0.2") {
		t.Error("Unexpected result for unlisted IP")
	}
	if lines := capturedErrors(); len(lines) > 0 {
		t.Errorf("unlisted IP produced error-level log lines: %q", lines)
	}
}

func TestRblInvalidIPSkipsLookup(t *testing.T) {
	var dialed atomic.Bool
	op := &rbl{
		service: "xbl.spamhaus.org",
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dialed.Store(true)
				return nil, context.Canceled
			},
		},
	}
	tx := corazawaf.NewWAF().NewTransaction()
	if op.Evaluate(tx, "not-an-ip") {
		t.Error("Unexpected result for non-IP input")
	}
	if dialed.Load() {
		t.Error("Resolver was invoked for non-IP input")
	}
}

// hangingResolver blocks every dial until the lookup context is cancelled,
// so each Evaluate call runs into its timeout.
func hangingResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
}

func TestRblTimeout(t *testing.T) {
	op := &rbl{service: "xbl.spamhaus.org", resolver: hangingResolver()}
	tx := corazawaf.NewWAF().NewTransaction()

	start := time.Now()
	if op.Evaluate(tx, "127.0.0.2") {
		t.Error("Unexpected result for timed out lookup")
	}
	if elapsed := time.Since(start); elapsed < timeout {
		t.Errorf("Evaluate returned before the timeout: %v", elapsed)
	}
}

// stableGoroutineCount waits out goroutines still winding down from earlier
// tests and returns a goroutine count that held steady across several samples.
func stableGoroutineCount(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	last := runtime.NumGoroutine()
	for stable := 0; stable < 5 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
		if n := runtime.NumGoroutine(); n == last {
			stable++
		} else {
			stable = 0
			last = n
		}
	}
	return last
}

// waitForGoroutineBaseline polls until the goroutine count drops to at most
// baseline+slack, failing the test if it does not settle before the deadline.
func waitForGoroutineBaseline(t *testing.T, baseline, slack int, deadline time.Duration) {
	t.Helper()
	limit := time.Now().Add(deadline)
	for {
		if runtime.NumGoroutine() <= baseline+slack {
			return
		}
		if time.Now().After(limit) {
			t.Fatalf("goroutine count did not settle: baseline=%d, now=%d", baseline, runtime.NumGoroutine())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRblTimeoutDoesNotLeakGoroutines(t *testing.T) {
	op := &rbl{service: "xbl.spamhaus.org", resolver: hangingResolver()}

	before := stableGoroutineCount(t)

	const evaluations = 5
	var wg sync.WaitGroup
	for i := 0; i < evaluations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx := corazawaf.NewWAF().NewTransaction()
			if op.Evaluate(tx, "127.0.0.2") {
				t.Error("Unexpected result for timed out lookup")
			}
		}()
	}
	wg.Wait()

	// Goroutine teardown is asynchronous: poll until the count settles.
	// A leak pins one goroutine per evaluation, so the tolerance must stay
	// strictly below evaluations to keep the assertion falsifiable.
	waitForGoroutineBaseline(t, before, evaluations-1, 3*time.Second)
}

func TestRblCancelledLookupDoesNotLogError(t *testing.T) {
	op := &rbl{
		service: "xbl.spamhaus.org",
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, context.Canceled
			},
		},
	}

	waf, capturedErrors := errorCapturingWAF()
	tx := waf.NewTransaction()
	if op.Evaluate(tx, "127.0.0.2") {
		t.Error("Unexpected result for a cancelled lookup")
	}
	if lines := capturedErrors(); len(lines) > 0 {
		t.Errorf("a cancelled lookup logged at error level: %v", lines)
	}
}

func TestRblTimeoutLeavesTransactionUntouched(t *testing.T) {
	op := &rbl{service: "xbl.spamhaus.org", resolver: hangingResolver()}

	waf, capturedErrors := errorCapturingWAF()
	tx := waf.NewTransaction()
	if op.Evaluate(tx, "127.0.0.2") {
		t.Error("Unexpected result for a lookup slower than the timeout")
	}
	if got := tx.Variables().TX().Get("httpbl_msg"); len(got) > 0 {
		t.Errorf("a timed out lookup set httpbl_msg: %q", got)
	}
	// A slow or unreachable RBL is the service being slow, not an engine
	// failure, so it must not write an error line per request.
	if lines := capturedErrors(); len(lines) > 0 {
		t.Errorf("a timed out lookup logged at error level: %v", lines)
	}
}
