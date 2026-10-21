// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package experimental_test

import (
	"reflect"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// rxPreFilterProbe stands in for an @rx whose prefilter was wrong: no ruleset can
// make the real one wrong, so this operator reports a miss through the hook the
// engine gives operators, as @rx does, every time it is evaluated.
type rxPreFilterProbe struct{ miss func() }

func (p rxPreFilterProbe) Evaluate(plugintypes.TransactionState, string) bool {
	if p.miss != nil {
		p.miss()
	}
	return true
}

func TestRxPreFilterObserver(t *testing.T) {
	plugins.RegisterOperator("rxprefilterprobe", func(o plugintypes.OperatorOptions) (plugintypes.Operator, error) {
		return rxPreFilterProbe{miss: o.RxPreFilterMiss}, nil
	})

	testCases := map[string]struct {
		directives   string
		withObserver bool
		want         []int
	}{
		"rule ID, and the chain starter's ID for a chained rule": {
			directives: `
				SecRxPreFilter On
				SecRxPreFilterVerify 100
				SecRule ARGS "@rxprefilterprobe" "id:4242,phase:1,pass"
				SecRule ARGS "@rx ." "id:4243,phase:1,pass,chain"
				SecRule ARGS "@rxprefilterprobe" ""
			`,
			withObserver: true,
			want:         []int{4242, 4243},
		},
		"verification at a fraction still reaches the observer": {
			directives: `
				SecRxPreFilter On
				SecRxPreFilterVerify 0.5
				SecRule ARGS "@rxprefilterprobe" "id:4244,phase:1,pass"
			`,
			withObserver: true,
			want:         []int{4244},
		},
		"verification at 0: the operator has no hook": {
			directives: `
				SecRxPreFilter On
				SecRule ARGS "@rxprefilterprobe" "id:4245,phase:1,pass"
			`,
			withObserver: true,
		},
		"prefilter off: the operator has no hook": {
			directives: `
				SecRxPreFilter Off
				SecRxPreFilterVerify 100
				SecRule ARGS "@rxprefilterprobe" "id:4246,phase:1,pass"
			`,
			withObserver: true,
		},
		"no observer configured: a miss is harmless": {
			directives: `
				SecRxPreFilter On
				SecRxPreFilterVerify 100
				SecRule ARGS "@rxprefilterprobe" "id:4247,phase:1,pass"
			`,
			withObserver: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			var got []int

			cfg := coraza.NewWAFConfig().
				WithDirectives("SecRuleEngine On\n" + tc.directives)
			if tc.withObserver {
				cfg = experimental.WAFConfigWithRxPreFilterObserver(cfg, func(ruleID int) {
					got = append(got, ruleID)
				})
			}

			waf, err := coraza.NewWAF(cfg)
			if err != nil {
				t.Fatalf("unexpected error creating WAF: %v", err)
			}

			tx := waf.NewTransaction()
			defer tx.Close()
			tx.ProcessURI("/?a=1", "GET", "HTTP/1.1")
			tx.ProcessRequestHeaders()

			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("observer got rule IDs %v, want %v", got, tc.want)
			}
		})
	}
}
