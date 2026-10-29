// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package plugintypes

import "io/fs"

// Memoizer caches the result of expensive function calls by key.
// Implementations must be safe for concurrent use.
type Memoizer interface {
	Do(key string, fn func() (any, error)) (any, error)
}

// OperatorOptions is used to store the options for a rule operator
type OperatorOptions struct {
	// Arguments stores the operator args.
	Arguments string

	// Path stores a list of possible data paths.
	Path []string

	// Root is the root to resolve Path from.
	Root fs.FS

	// Datasets contains input datasets or dictionaries.
	Datasets map[string][]string

	// Memoizer caches expensive compilations (regex, aho-corasick).
	Memoizer Memoizer

	// RxPreFilterEnabled controls whether the @rx operator uses
	// literal pre-filtering. Set by the SecRxPreFilter directive.
	RxPreFilterEnabled bool

	// RxPreFilterVerify is the probability, from 0 to 1, that the @rx operator
	// runs its regular expression anyway when the prefilter says the input
	// cannot match. A match proves the prefilter wrong. Set by the
	// SecRxPreFilterVerify directive.
	RxPreFilterVerify float64

	// RxPreFilterMiss is called when such a check finds a match. The operator
	// calls it at most once and then stops using its prefilter. It carries no
	// request data. It is nil unless RxPreFilterEnabled is set and
	// RxPreFilterVerify is above zero.
	RxPreFilterMiss func()

	// RxRE2 makes the @rx operator match with RE2 in Latin-1 mode instead of
	// Go's regexp. Set by the SecRxEngine directive.
	RxRE2 bool
}

// Operator interface is used to define rule @operators
type Operator interface {
	// Evaluate is used during the rule evaluation,
	// it returns true if the operator succeeded against
	// the input data for the transaction
	Evaluate(TransactionState, string) bool
}

type OperatorFactory func(options OperatorOptions) (Operator, error)
