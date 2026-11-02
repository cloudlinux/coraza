// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// TestJSONArgumentsLimitMatchesModSecurity runs JSON bodies around
// SecArgumentsLimit through a deny rule on REQBODY_ERROR. The expected ARGS
// counts and verdicts were measured on ModSecurity 2.9.7 (Debian 12 package)
// with the same rules and the default limit of 1000.
func TestJSONArgumentsLimitMatchesModSecurity(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "@rx ^application/json" "id:1,phase:1,pass,nolog,t:none,t:lowercase,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "!@eq 0" "id:2,phase:2,deny,status:400,log"
`))
	if err != nil {
		t.Fatal(err)
	}

	values := func(n int) string {
		items := make([]string, n)
		for i := range items {
			items[i] = strconv.Itoa(i)
		}
		return `{"a":[` + strings.Join(items, ",") + `]}`
	}
	query := func(n int) string {
		pairs := make([]string, n)
		for i := range pairs {
			pairs[i] = fmt.Sprintf("q%d=v", i)
		}
		return strings.Join(pairs, "&")
	}
	oneElementArrays := func(n int) string {
		members := make([]string, n)
		for i := range members {
			members[i] = fmt.Sprintf(`"a%d":[1]`, i)
		}
		return "{" + strings.Join(members, ",") + "}"
	}

	tests := []struct {
		name     string
		query    string
		body     string
		wantArgs int
		wantDeny bool
	}{
		{name: "1001 values", body: values(1001), wantArgs: 1000, wantDeny: true},
		{name: "1000 values then empty containers", body: values(1000)[:len(values(1000))-1] + `,"b":{},"c":[]}`, wantArgs: 1000},
		{name: "10 query args and 990 values", query: query(10), body: values(990), wantArgs: 1000},
		{name: "10 query args and 995 values", query: query(10), body: values(995), wantArgs: 1000, wantDeny: true},
		{name: "1000 query args and a value", query: query(1000), body: `{"a":1}`, wantArgs: 1000, wantDeny: true},
		{name: "1000 query args and no value", query: query(1000), body: `{"a":{}}`, wantArgs: 1000},
		{name: "999 one-element arrays", body: oneElementArrays(999), wantArgs: 999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := waf.NewTransaction()
			defer tx.Close()
			uri := "/t"
			if tt.query != "" {
				uri += "?" + tt.query
			}
			tx.ProcessURI(uri, "POST", "HTTP/1.1")
			tx.AddRequestHeader("Content-Type", "application/json")
			if it := tx.ProcessRequestHeaders(); it != nil {
				t.Fatalf("unexpected interruption in phase 1: %v", it)
			}
			if _, _, err := tx.WriteRequestBody([]byte(tt.body)); err != nil {
				t.Fatal(err)
			}
			it, err := tx.ProcessRequestBody()
			if err != nil {
				t.Fatal(err)
			}
			if denied := it != nil && it.Status == 400; denied != tt.wantDeny {
				t.Errorf("denied = %v, want %v", denied, tt.wantDeny)
			}
			args := tx.(plugintypes.TransactionState).Variables().Args().FindAll()
			if len(args) != tt.wantArgs {
				t.Errorf("ARGS holds %d values, want %d", len(args), tt.wantArgs)
			}
		})
	}
}
