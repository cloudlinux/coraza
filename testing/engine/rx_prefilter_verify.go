// Copyright 2026 CloudLinux
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

// With SecRxPreFilterVerify at 100 every decision of the @rx prefilter is checked
// against the regex, so the rules must match exactly as they do with the prefilter
// off. The report of a wrong prefilter itself is covered next to the operator
// (internal/operators) and through the public API (experimental), because no
// ruleset can make the prefilter wrong.
var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "ggrigoras-ops",
		Description: "Test that @rx matches the same with SecRxPreFilter On and every skip verified",
		Enabled:     true,
		Name:        "rx_prefilter_verify.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "a match the prefilter lets through",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?q=select+sleep(5)",
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
			Title: "a value the prefilter skips, checked against the regex, stays unmatched",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?q=a+perfectly+ordinary+value",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
		{
			Title: "a value that has the literal but not the pattern stays unmatched",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?q=sleep+well",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
		{
			Title: "the exact-literal shortcut matches the literal",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?q=Upload",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{2},
							NonTriggeredRules: []int{1},
						},
					},
				},
			},
		},
		{
			Title: "the exact-literal shortcut does not match another value",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/?q=xUpload",
							Method: "GET",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
	Rules: `
SecRxPreFilter On
SecRxPreFilterVerify 100
SecRule ARGS "@rx sleep\s*\(" "id:1, phase:1, pass, log"
SecRule ARGS "@rx ^Upload$" "id:2, phase:1, pass, log"
`,
})
