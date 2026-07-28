// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

//go:build !tinygo

package persistence_test

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/persistence"
	"github.com/corazawaf/coraza/v3/experimental/persistence/ptypes"
)

// SetEngine documents a nil engine as disabling persistence. The persistent
// collections dereference the engine unconditionally, so a provider handing back
// nil used to panic on the first rule that reached one - initcol and setvar
// always could, and selecting a key has been able to since the collections were
// marked selectable.
func TestNilEngineFromProviderDisablesPersistence(t *testing.T) {
	config, err := persistence.SetEngine(
		coraza.NewWAFConfig().WithDirectives(`SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,initcol:ip=%{REMOTE_ADDR}"
SecAction "id:2,phase:1,pass,nolog,setvar:'ip.hits=+1'"
SecRule IP:hits "@ge 1" "id:3,phase:1,pass,nolog"
`),
		func() (ptypes.PersistentEngine, error) { return nil, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	waf, err := coraza.NewWAF(config)
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	tx.ProcessConnection("1.1.1.1", 12345, "127.0.0.1", 80)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if err := tx.Close(); err != nil {
		t.Fatal(err)
	}

	if err := persistence.ClosePersistentEngine(waf); err != nil {
		t.Error(err)
	}
}
