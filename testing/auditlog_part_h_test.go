// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

// Audit logs are currently disabled for tinygo

//go:build !tinygo

package testing

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/corazawaf/coraza/v3/internal/auditlog"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/internal/seclang"
	"github.com/corazawaf/coraza/v3/types"
)

// TestAuditLogPartHRichMessages pins this fork's ModSecurity-v3-compatible
// part-H serialization: when SecAuditLogParts enables H but not K, every
// matched rule must be serialized into audit_data.messages[] as a full object
// (id, msg, severity, tags, raw, ...) rather than a bare error_message with
// "data": null. The Imunify agent parses the rich form; losing it (e.g. by
// resolving a future upstream merge conflict in Transaction.AuditLog toward
// the upstream H-only branch) breaks agent-side rule attribution silently,
// so this test must keep failing on the error-message-only shape.
func TestAuditLogPartHRichMessages(t *testing.T) {
	waf := corazawaf.NewWAF()
	parser := seclang.NewParser(waf)
	if err := parser.FromString(`
		SecRuleEngine DetectionOnly
		SecAuditEngine On
		SecAuditLogFormat json
		SecAuditLogType serial
		SecAuditLogParts AHZ
		SecAuditLogRelevantStatus ".*"
		SecRule ARGS "@unconditionalMatch" "id:100,phase:1,log,auditlog,msg:'fork rich message',severity:'CRITICAL',tag:'fork-part-h'"
	`); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "tmp.log")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := parser.FromString(fmt.Sprintf("SecAuditLog %s", file.Name())); err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	tx.AddGetRequestArgument("test", "test")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()

	if _, err := file.Seek(0, 0); err != nil {
		t.Error(err)
	}
	var al auditlog.Log
	if err := json.NewDecoder(file).Decode(&al); err != nil {
		t.Error(err)
	}
	if len(al.Messages()) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(al.Messages()))
	}
	msg, ok := al.Messages()[0].(auditlog.Message)
	if !ok {
		t.Fatalf("Expected message of type auditlog.Message, got %T", al.Messages()[0])
	}
	if msg.Message_ != "fork rich message" {
		t.Errorf("Expected message 'fork rich message', got %q", msg.Message_)
	}
	if msg.Data_ == nil {
		t.Fatal("part-H message has data: null — expected a rich data object with full rule metadata")
	}
	if msg.Data_.ID_ != 100 {
		t.Errorf("Expected data.id 100, got %d", msg.Data_.ID_)
	}
	if msg.Data_.Severity_ != types.RuleSeverityCritical {
		t.Errorf("Expected data.severity CRITICAL, got %v", msg.Data_.Severity_)
	}
	if len(msg.Data_.Tags_) != 1 || msg.Data_.Tags_[0] != "fork-part-h" {
		t.Errorf("Expected data.tags [fork-part-h], got %v", msg.Data_.Tags_)
	}
	if msg.Data_.Raw_ == "" {
		t.Error("Expected data.raw to contain the raw rule text, got empty string")
	}
}
