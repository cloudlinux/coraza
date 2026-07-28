// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/environment"
	"github.com/corazawaf/coraza/v3/types"
)

// makeTruncateTx builds a transaction with an urlencoded body already
// analyzed by ProcessRequestBody. memLimit <= 0 keeps the WAF default
// (in-memory buffering).
func makeTruncateTx(t *testing.T, memLimit int64, body string) *Transaction {
	t.Helper()
	waf := NewWAF()
	if memLimit > 0 {
		waf.SetRequestBodyInMemoryLimit(memLimit)
	}
	tx := waf.NewTransaction()
	tx.RequestBodyAccess = true
	tx.AuditLogParts = types.AuditLogParts("ABCFHZ")
	tx.ProcessURI("/", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Close() })
	return tx
}

func TestTruncateRequestBodyInMemory(t *testing.T) {
	body := "key=" + strings.Repeat("v", 64*1024)
	tx := makeTruncateTx(t, 0, body)

	if got := tx.requestBodyBuffer.buffer.Cap(); got < len(body) {
		t.Fatalf("test setup: expected in-memory buffer capacity >= %d, got %d", len(body), got)
	}

	const limit = 16
	if err := tx.TruncateRequestBody(limit); err != nil {
		t.Fatal(err)
	}

	if got := tx.requestBodyBuffer.Size(); got != limit {
		t.Errorf("buffer size: want %d, got %d", limit, got)
	}
	if got := tx.requestBodyBuffer.buffer.Cap(); got > 1024 {
		t.Errorf("backing array not released: capacity still %d", got)
	}
	if got := tx.variables.requestBody.Get(); got != body[:limit] {
		t.Errorf("REQUEST_BODY: want %q, got %q", body[:limit], got)
	}
	if got := tx.variables.requestBodyLength.Get(); got != strconv.Itoa(len(body)) {
		t.Errorf("REQUEST_BODY_LENGTH: want %d, got %s", len(body), got)
	}
	// parsed derivatives stay intact
	if got := tx.variables.argsPost.Get("key"); len(got) != 1 || got[0] != body[4:] {
		t.Error("ARGS_POST was affected by truncation")
	}
	// audit part C carries exactly the preview
	if got := tx.AuditLog().Transaction_.Request_.Body_; got != body[:limit] {
		t.Errorf("audit part C: want %q, got %q", body[:limit], got)
	}

	// idempotency: repeated and larger-limit calls are no-ops
	for _, l := range []int64{limit, limit + 100} {
		if err := tx.TruncateRequestBody(l); err != nil {
			t.Fatal(err)
		}
		if got := tx.variables.requestBody.Get(); got != body[:limit] {
			t.Errorf("REQUEST_BODY changed after TruncateRequestBody(%d): %q", l, got)
		}
	}
}

func TestTruncateRequestBodyInMemoryDiscard(t *testing.T) {
	body := "key=" + strings.Repeat("v", 64*1024)
	tx := makeTruncateTx(t, 0, body)

	if err := tx.TruncateRequestBody(0); err != nil {
		t.Fatal(err)
	}
	if got := tx.requestBodyBuffer.Size(); got != 0 {
		t.Errorf("buffer size: want 0, got %d", got)
	}
	if got := tx.requestBodyBuffer.buffer.Cap(); got != 0 {
		t.Errorf("backing array not released: capacity still %d", got)
	}
	if got := tx.variables.requestBody.Get(); got != "" {
		t.Errorf("REQUEST_BODY: want empty, got %q", got)
	}
	if got := tx.AuditLog().Transaction_.Request_.Body_; got != "" {
		t.Errorf("audit part C: want empty, got %q", got)
	}
}

func TestTruncateRequestBodyFile(t *testing.T) {
	if !environment.HasAccessToFS {
		return // t.Skip doesn't work on TinyGo
	}
	body := "key=" + strings.Repeat("v", 1024)
	tx := makeTruncateTx(t, 8, body)

	f := tx.requestBodyBuffer.writer
	if f == nil {
		t.Fatal("test setup: expected file-backed body buffer")
	}

	const limit = 16
	if err := tx.TruncateRequestBody(limit); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(f.Name()); err != nil {
		t.Fatal(err)
	} else if st.Size() != limit {
		t.Errorf("tmp file size: want %d, got %d", limit, st.Size())
	}
	if got := tx.requestBodyBuffer.Size(); got != limit {
		t.Errorf("buffer size: want %d, got %d", limit, got)
	}
	if got := tx.AuditLog().Transaction_.Request_.Body_; got != body[:limit] {
		t.Errorf("audit part C: want %q, got %q", body[:limit], got)
	}
}

func TestTruncateRequestBodyFileDiscard(t *testing.T) {
	if !environment.HasAccessToFS {
		return // t.Skip doesn't work on TinyGo
	}
	body := "key=" + strings.Repeat("v", 1024)
	tx := makeTruncateTx(t, 8, body)

	f := tx.requestBodyBuffer.writer
	if f == nil {
		t.Fatal("test setup: expected file-backed body buffer")
	}
	if err := tx.TruncateRequestBody(0); err != nil {
		t.Fatal(err)
	}
	if tx.requestBodyBuffer.writer != nil {
		t.Error("tmp file writer not released")
	}
	if _, err := os.Stat(f.Name()); err == nil {
		t.Error("tmp file was not deleted")
	}
	if got := tx.requestBodyBuffer.Size(); got != 0 {
		t.Errorf("buffer size: want 0, got %d", got)
	}
}

func TestTruncateRequestBodyBeforeProcessing(t *testing.T) {
	tx := NewWAF().NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true
	tx.ProcessURI("/", "POST", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("key=value")); err != nil {
		t.Fatal(err)
	}

	if err := tx.TruncateRequestBody(0); err == nil {
		t.Error("expected error when called before ProcessRequestBody")
	}
	if got := tx.requestBodyBuffer.Size(); got != int64(len("key=value")) {
		t.Errorf("body must stay untouched on error, size: %d", got)
	}
}

// Readers obtained before truncation are invalidated: whether consumed or
// untouched, they must fail with ErrBodyTruncated on the next read instead
// of panicking or quietly serving the prefix/EOF.
func TestTruncateRequestBodyStaleReader(t *testing.T) {
	tx := makeTruncateTx(t, 0, "key="+strings.Repeat("v", 1024))

	consumed, err := tx.RequestBodyReader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, consumed); err != nil {
		t.Fatal(err)
	}
	untouched, err := tx.RequestBodyReader()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.TruncateRequestBody(4); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]io.Reader{"consumed": consumed, "untouched": untouched} {
		n, err := r.Read(make([]byte, 8))
		if n != 0 || !errors.Is(err, types.ErrBodyTruncated) {
			t.Errorf("%s stale reader: want (0, ErrBodyTruncated), got (%d, %v)", name, n, err)
		}
	}
}

func TestTruncateRequestBodyNegativeLimit(t *testing.T) {
	tx := makeTruncateTx(t, 0, "key=value")
	if err := tx.TruncateRequestBody(-1); err == nil {
		t.Error("expected error for negative limit")
	}
}

// With the rule engine off, ProcessRequestBody skips rule evaluation and
// lastPhase never advances; truncation must still be accepted.
func TestTruncateRequestBodyEngineOff(t *testing.T) {
	waf := NewWAF()
	waf.RuleEngine = types.RuleEngineOff
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true
	tx.ProcessURI("/", "POST", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("key=value")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if err := tx.TruncateRequestBody(0); err != nil {
		t.Errorf("engine off: unexpected error: %v", err)
	}
}

// On an interrupted transaction ProcessRequestBody returns early without
// evaluating rules; truncation must still be accepted.
func TestTruncateRequestBodyInterrupted(t *testing.T) {
	tx := NewWAF().NewTransaction()
	defer tx.Close()
	tx.RequestBodyAccess = true
	tx.ProcessURI("/", "POST", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody([]byte("key=value")); err != nil {
		t.Fatal(err)
	}
	tx.interruption = &types.Interruption{Action: "deny"}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatal(err)
	}
	if err := tx.TruncateRequestBody(0); err != nil {
		t.Errorf("interrupted: unexpected error: %v", err)
	}
	if got := tx.requestBodyBuffer.Size(); got != 0 {
		t.Errorf("buffer size: want 0, got %d", got)
	}
}

// Even when closing the temp file fails, the file must still be removed:
// br.writer is already nil at that point, so Reset() would never clean it up.
func TestTruncateRequestBodyCloseFailureStillRemovesFile(t *testing.T) {
	if !environment.HasAccessToFS {
		return // t.Skip doesn't work on TinyGo
	}
	tx := makeTruncateTx(t, 8, "key="+strings.Repeat("v", 1024))

	f := tx.requestBodyBuffer.writer
	if err := f.Close(); err != nil { // makes the buffer's own Close fail
		t.Fatal(err)
	}
	if err := tx.TruncateRequestBody(0); err == nil {
		t.Error("expected error from failing Close")
	}
	if tx.requestBodyBuffer.writer != nil {
		t.Error("tmp file writer not released")
	}
	if _, err := os.Stat(f.Name()); err == nil {
		t.Error("tmp file was not deleted")
	}
}

// A failing file truncation must leave the buffer untouched: size keeps the
// original value and outstanding readers are not invalidated.
func TestTruncateRequestBodyFileTruncateFailureKeepsState(t *testing.T) {
	if !environment.HasAccessToFS {
		return // t.Skip doesn't work on TinyGo
	}
	body := "key=" + strings.Repeat("v", 1024)
	tx := makeTruncateTx(t, 8, body)

	r, err := tx.RequestBodyReader()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.requestBodyBuffer.writer.Close(); err != nil { // makes Truncate fail
		t.Fatal(err)
	}
	if err := tx.TruncateRequestBody(16); err == nil {
		t.Error("expected error from failing file truncation")
	}
	if got := tx.requestBodyBuffer.Size(); got != int64(len(body)) {
		t.Errorf("buffer size: want %d, got %d", len(body), got)
	}
	if _, err := r.Read(make([]byte, 1)); errors.Is(err, types.ErrBodyTruncated) {
		t.Error("reader invalidated although nothing was truncated")
	}
}
