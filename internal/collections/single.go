// Copyright 2023 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package collections

import (
	"fmt"
	"strings"

	"github.com/corazawaf/coraza/v3/collection"
	"github.com/corazawaf/coraza/v3/internal/corazarules"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type Single struct {
	data     string
	variable variables.RuleVariable
	// matches is FindAll's result for data, built when data changes.
	matches []types.MatchData
}

var _ collection.Single = &Single{}

// NewSingle creates a new Single.
func NewSingle(variable variables.RuleVariable) *Single {
	return &Single{
		variable: variable,
	}
}

// FindAll returns the value as a single match. The result is shared by every
// FindAll until the value changes, so callers must not modify it.
func (c *Single) FindAll() []types.MatchData {
	if c.matches == nil || c.matches[0].Value() != c.data {
		c.matches = []types.MatchData{&corazarules.MatchData{
			Variable_: c.variable,
			Value_:    c.data,
		}}
	}
	return c.matches
}

func (c *Single) Get() string {
	return c.data
}

func (c *Single) Set(value string) {
	c.data = value
}

func (c *Single) Name() string {
	return c.variable.Name()
}

func (c *Single) Reset() {
	c.data = ""
	c.matches = nil
}

func (c *Single) Format(res *strings.Builder) {
	res.WriteString(c.variable.Name())
	res.WriteString(": ")
	res.WriteString(c.data)
}

func (c *Single) String() string {
	return fmt.Sprintf("%s: %s", c.variable.Name(), c.data)
}
