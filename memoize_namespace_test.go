// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package coraza

import "testing"

// The memoize cache is one flat string-keyed namespace shared by every call
// site in the tree, and the sites store different Go types under it. A pattern
// text that reaches two of them therefore has to land on two distinct keys:
// whichever site compiled first would otherwise hand its value to the second,
// which type-asserts it and panics inside NewWAF.
//
// These assertions live at the NewWAF level because that is the only level
// where a memoizer is wired up - the operator and rule constructors take one
// as an argument and skip caching entirely when it is nil.
func TestMemoizeKeysAreNamespacedPerCallSite(t *testing.T) {
	for _, tc := range []struct {
		name       string
		directives string
	}{
		{
			// @pm caches an aho-corasick automaton and a variable selector
			// caches a *regexp.Regexp, both from the bare pattern text.
			name: "pm then variable selector",
			directives: `SecRule ARGS:content|ARGS:data "@pm _id" "id:1,phase:2,pass,nolog"
SecRule ARGS:/_id/ "@detectSQLi" "id:2,phase:2,pass,nolog"`,
		},
		{
			name: "variable selector then pm",
			directives: `SecRule ARGS:/_zz/ "@detectSQLi" "id:1,phase:2,pass,nolog"
SecRule ARGS:content "@pm _zz" "id:2,phase:2,pass,nolog"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewWAF(NewWAFConfig().WithDirectives("SecRuleEngine On\n" + tc.directives + "\n")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// @pm keys on a literal dictionary and @pmFromDataset on a dataset name. Both
// cache an aho-corasick automaton, so a shared key raises no type error - the
// second operator silently enforces the first one's patterns instead of its
// own, and the traffic it was meant to catch passes.
func TestMemoizePmAndDatasetDoNotShareAKey(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`SecRuleEngine On
SecDataset evil ` + "`" + `
attackpayload
` + "`" + `
SecRule ARGS "@pm evil" "id:1,phase:2,deny,status:403,log"
SecRule ARGS "@pmFromDataset evil" "id:2,phase:2,deny,status:403,log"
`))
	if err != nil {
		t.Fatal(err)
	}

	tx := waf.NewTransaction()
	defer func() { _ = tx.Close() }()
	tx.ProcessURI("/?q=attackpayload", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()
	if it, _ := tx.ProcessRequestBody(); it == nil {
		t.Fatal("@pmFromDataset did not match its dataset contents")
	}
}
