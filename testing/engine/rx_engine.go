// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// SecRxEngine applies to the rules defined after it. Rule 1 matches with re2,
// which counts bytes, rule 2 with stdlib, which counts UTF-8 characters, so a
// three-byte character tells them apart.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "amurashkin",
		Description: "Test that SecRxEngine selects the @rx engine of the rules after it",
		Enabled:     true,
		Name:        "rx_engine.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "a multi-byte character is three bytes but one character",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?a=%E6%97%A5",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{1},
							NonTriggeredRules: []int{2},
						},
					},
				},
			},
		},
		{
			Title: "three ASCII characters match with both engines",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?a=abc",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRuleEngine On
SecRxEngine re2
SecRule ARGS:a "@rx ^.{3}$" "id:1,phase:1,log,pass"
SecRxEngine stdlib
SecRule ARGS:a "@rx ^.{3}$" "id:2,phase:1,log,pass"
`,
})
