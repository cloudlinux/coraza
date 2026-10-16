// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package experimental

import (
	"github.com/corazawaf/coraza/v3"
)

// wafConfigWithRxPreFilterObserver is the private capability interface
type wafConfigWithRxPreFilterObserver interface {
	WithRxPreFilterObserver(func(ruleID int)) coraza.WAFConfig
}

// WAFConfigWithRxPreFilterObserver sets the function that is called when the
// verification of the @rx pre-filter (SecRxPreFilterVerify) finds that the
// pre-filter rejected an input a regular expression matches. It receives the ID
// of the rule (the chain starter's for a chained rule) and nothing about the
// request. The rule is evaluated without the pre-filter from then on, until the
// rules are loaded again, so the function is called at most once per rule and WAF.
//
// It may run on any goroutine that evaluates rules, so it has to be safe for
// concurrent use and must not block. It returns cfg unchanged if the
// configuration does not support the observer.
func WAFConfigWithRxPreFilterObserver(
	cfg coraza.WAFConfig,
	observer func(ruleID int),
) coraza.WAFConfig {
	if c, ok := cfg.(wafConfigWithRxPreFilterObserver); ok {
		return c.WithRxPreFilterObserver(observer)
	}
	return cfg
}
